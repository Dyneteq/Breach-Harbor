package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/agent"
	"github.com/Dyneteq/Breach-Harbor/internal/feed"
	"github.com/Dyneteq/Breach-Harbor/internal/firewall"
	"github.com/Dyneteq/Breach-Harbor/internal/logsource"
	"github.com/Dyneteq/Breach-Harbor/internal/services"
	"github.com/Dyneteq/Breach-Harbor/internal/store"

	"gorm.io/gorm"
)

// ErrLocalAgentDisabled is returned by every LocalAgentManager method
// when the operator hasn't opted in (`server run --local-agent`). The
// feature lets any logged-in user cause this process to mutate the
// host's own firewall (once they flip SetEnforce) — since this app
// has open self-registration and no admin/role concept
// (models.User has none), that must never be reachable by default;
// only an operator who explicitly passed --local-agent has made that
// call.
var ErrLocalAgentDisabled = errors.New("local agent is disabled — the operator must start the server with `server run --local-agent` to enable it")

// ErrLocalAgentNotOwner is returned by Stop/SetEnforce when the
// caller isn't the user who started the currently-running local
// agent — without this, any authenticated user could stop or
// reconfigure (including flip on real firewall enforcement for)
// another user's already-running local agent.
var ErrLocalAgentNotOwner = errors.New("only the user who started the local agent may stop or reconfigure it")

// LocalAgentManager lets the server start/stop a real agent.Agent
// in-process, against the machine the server itself is running on —
// a one-click way to get local detection going without a separate
// `breachharbor agent run` invocation or an `agent enroll` round trip.
// Its observations are persisted through collectorService directly
// (in-process, no HTTP/token hop) under a per-user collector so they
// show up in Incidents/IP Addresses exactly like any other collector.
type LocalAgentManager struct {
	dataDir          string
	collectorService *services.CollectorService
	enabled          bool

	mu          sync.Mutex
	cancel      context.CancelFunc
	done        chan struct{}
	st          store.AgentStore
	a           *agent.Agent
	collectorID uint
	collector   string
	startedBy   uint
	startedAt   time.Time
	enforcing   bool
	lastErr     error

	logMu    sync.Mutex
	logLines []LocalAgentLogLine
	logSeq   uint64
}

// localAgentLogCapacity bounds the in-memory scrollback kept for the
// terminal view (templates/local_agent.html's live log panel): old
// lines fall off the front once exceeded, same trade-off as any
// tail -f buffer; nothing here is persisted to disk or the DB.
const localAgentLogCapacity = 500

// localAgentLogLinePattern splits a rendered agent.Agent.emit() line
// back into its columns. Agent.emit's own doc comment (internal/agent/
// agent.go) states this "HH:MM:SS, left-aligned tag, free-form
// message" shape as the stable contract every log line follows, so
// parsing it back out here (rather than threading structured fields
// through the Logf callback) is safe.
var localAgentLogLinePattern = regexp.MustCompile(`^\S+\s+(\S+)\s+(.*)$`)

// LocalAgentLogLine is one line of the running agent's live status
// log, captured for the terminal panel. Seq is a monotonic cursor a
// client can pass back as `since` to fetch only what's new.
type LocalAgentLogLine struct {
	Seq     uint64    `json:"seq"`
	Time    time.Time `json:"time"`
	Tag     string    `json:"tag"`
	Message string    `json:"message"`
}

// appendLogLine records one rendered log line for the terminal panel.
// Called from the agent's own Logf callback, so it must not block on
// anything the agent's run loop could be holding.
func (m *LocalAgentManager) appendLogLine(rendered string) {
	tag, message := "", rendered
	if match := localAgentLogLinePattern.FindStringSubmatch(rendered); match != nil {
		tag, message = match[1], match[2]
	}

	m.logMu.Lock()
	defer m.logMu.Unlock()
	m.logSeq++
	m.logLines = append(m.logLines, LocalAgentLogLine{
		Seq:     m.logSeq,
		Time:    time.Now(),
		Tag:     tag,
		Message: message,
	})
	if len(m.logLines) > localAgentLogCapacity {
		m.logLines = m.logLines[len(m.logLines)-localAgentLogCapacity:]
	}
}

// resetLog clears the scrollback, called at the start of every Start()
// so a fresh run's terminal view doesn't open with a previous run's
// tail still in it.
func (m *LocalAgentManager) resetLog() {
	m.logMu.Lock()
	defer m.logMu.Unlock()
	m.logLines = nil
	m.logSeq = 0
}

// RecentLog returns every captured line with Seq > since (oldest
// first), plus the cursor to pass as `since` on the next call. Safe to
// call whether or not the agent is currently running: it just
// reflects whatever's left in the buffer.
func (m *LocalAgentManager) RecentLog(since uint64) ([]LocalAgentLogLine, uint64) {
	m.logMu.Lock()
	defer m.logMu.Unlock()
	if len(m.logLines) == 0 || since >= m.logSeq {
		return nil, m.logSeq
	}
	// logLines[0].Seq is the oldest surviving entry. since could be
	// older than that if the caller was gone long enough for the ring
	// buffer to wrap; start from the beginning in that case rather than
	// indexing negative.
	start := 0
	if since >= m.logLines[0].Seq {
		start = int(since - m.logLines[0].Seq + 1)
	}
	out := make([]LocalAgentLogLine, len(m.logLines)-start)
	copy(out, m.logLines[start:])
	return out, m.logSeq
}

// NewLocalAgentManager returns a manager that refuses every action
// until enabled is true — see ErrLocalAgentDisabled.
func NewLocalAgentManager(serverDataDir string, collectorService *services.CollectorService, enabled bool) *LocalAgentManager {
	return &LocalAgentManager{
		dataDir:          filepath.Join(serverDataDir, "local-agent"),
		collectorService: collectorService,
		enabled:          enabled,
	}
}

// LocalAgentStatus is the read-only snapshot rendered into
// templates/local_agent.html.
type LocalAgentStatus struct {
	Enabled       bool
	Running       bool
	Enforcing     bool
	StartedAt     time.Time
	Sources       []string
	Firewall      string
	CollectorName string
	LastError     string
}

func (m *LocalAgentManager) Status() LocalAgentStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := LocalAgentStatus{
		Enabled:       m.enabled,
		Running:       m.a != nil,
		Enforcing:     m.enforcing,
		StartedAt:     m.startedAt,
		CollectorName: m.collector,
	}
	if m.a != nil {
		st.Firewall = m.a.Firewall.Name()
		for _, src := range m.a.Sources {
			st.Sources = append(st.Sources, src.Name())
		}
	}
	if m.lastErr != nil {
		st.LastError = m.lastErr.Error()
	}
	return st
}

// localAgentCollectorName is deterministic per user (not just
// "local-agent") because models.Collector.Name is globally unique
// across every user on this server, not just per-user.
func localAgentCollectorName(userID uint) string {
	return fmt.Sprintf("local-agent-%d", userID)
}

// Start begins observing this host. It always starts in dry run
// (SetEnforce turns real blocking on afterward) — a web click should
// never be the thing that first arms a firewall backend.
func (m *LocalAgentManager) Start(userID uint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled {
		return ErrLocalAgentDisabled
	}
	if m.a != nil {
		err := fmt.Errorf("local agent is already running")
		m.lastErr = err
		return err
	}

	name := localAgentCollectorName(userID)
	collector, err := m.collectorService.GetCollectorByName(userID, name)
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			m.lastErr = fmt.Errorf("look up %s collector: %w", name, err)
			return m.lastErr
		}
		collector, _, err = m.collectorService.CreateCollector(userID, name, "127.0.0.1")
		if err != nil {
			m.lastErr = fmt.Errorf("create %s collector: %w", name, err)
			return m.lastErr
		}
	}

	fst, err := store.Open(m.dataDir)
	if err != nil {
		m.lastErr = fmt.Errorf("open local agent store at %s (a stale lock from a previous run?): %w", m.dataDir, err)
		return m.lastErr
	}

	cfg := agent.Default()
	cfg.DataDir = m.dataDir
	cfg.Enforce = false

	fw, fwErr := firewall.Detect(context.Background(), cfg.Firewall)
	if fwErr != nil {
		fw = unavailableBackend{err: fwErr}
	}

	sources := logsource.Detect(context.Background())
	feeds := []feed.Provider{
		feed.NewCachedProvider(feed.NewSpamhaus(), cfg.DataDir, 0),
		feed.NewCachedProvider(feed.NewFirehol(), cfg.DataDir, 0),
		feed.NewCachedProvider(feed.NewTor(), cfg.DataDir, 0),
	}

	m.resetLog()

	a := agent.New(cfg, fst, fw, feeds, sources)
	a.Logf = func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		log.Printf("[local-agent] %s", line)
		m.appendLogLine(line)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	m.cancel = cancel
	m.done = done
	m.a = a
	m.st = fst
	m.collectorID = collector.ID
	m.collector = collector.Name
	m.startedBy = userID
	m.startedAt = time.Now()
	m.enforcing = false
	m.lastErr = nil

	go m.runDrainLoop(ctx, fst, collector.ID)
	go func() {
		defer close(done)
		if runErr := a.Run(ctx); runErr != nil && ctx.Err() == nil {
			m.mu.Lock()
			m.lastErr = runErr
			m.mu.Unlock()
		}
	}()

	return nil
}

// Stop cancels the running agent, waits for its goroutines to exit,
// and releases the store's lock file. Only the user who started it
// may stop it (ErrLocalAgentNotOwner otherwise) — see stopLocked's
// skipOwnerCheck for the one exception, system shutdown.
func (m *LocalAgentManager) Stop(userID uint) error {
	return m.stop(userID, false)
}

// StopIfRunning is Stop without the "not running"/ownership checks —
// used only by Server.Close on process shutdown, where "nothing to
// stop" is a normal case and there is no HTTP caller to attribute the
// stop to.
func (m *LocalAgentManager) StopIfRunning() error {
	return m.stop(0, true)
}

func (m *LocalAgentManager) stop(userID uint, skipOwnerCheck bool) error {
	m.mu.Lock()
	if m.a == nil {
		if skipOwnerCheck {
			m.mu.Unlock()
			return nil
		}
		err := fmt.Errorf("local agent is not running")
		m.lastErr = err
		m.mu.Unlock()
		return err
	}
	if !skipOwnerCheck && userID != m.startedBy {
		m.mu.Unlock()
		return ErrLocalAgentNotOwner
	}
	cancel, done, fst := m.cancel, m.done, m.st
	m.mu.Unlock()

	cancel()
	<-done

	m.mu.Lock()
	defer m.mu.Unlock()
	err := fst.Close()
	m.a, m.st, m.cancel, m.done = nil, nil, nil, nil
	m.enforcing = false
	if err != nil {
		m.lastErr = fmt.Errorf("close local agent store: %w", err)
		return m.lastErr
	}
	m.lastErr = nil
	return nil
}

// SetEnforce flips the live agent between dry-run and enforcing by
// writing agent-state.json — the same mechanism `breachharbor agent
// enforce --on/--off` uses — which the running agent's Run loop
// reconciles within a few seconds (internal/agent.Agent.reconcileState).
// Only the user who started the agent may call this.
func (m *LocalAgentManager) SetEnforce(userID uint, on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.a == nil {
		err := fmt.Errorf("local agent is not running")
		m.lastErr = err
		return err
	}
	if userID != m.startedBy {
		return ErrLocalAgentNotOwner
	}

	state, err := agent.LoadState(m.dataDir)
	if err != nil {
		m.lastErr = err
		return err
	}
	state.Enforcing = on
	if on {
		if state.EnforcingSince == nil {
			now := time.Now()
			state.EnforcingSince = &now
		}
	} else {
		state.EnforcingSince = nil
	}
	if err := agent.SaveState(m.dataDir, state); err != nil {
		m.lastErr = err
		return err
	}

	m.enforcing = on
	m.lastErr = nil
	return nil
}

// runDrainLoop periodically hands the local agent's queued
// observations to collectorService directly — no HTTP hop, no bearer
// token, since this runs inside the same process that owns the
// database. It also reports the local agent's live firewall state on
// the same tick, the in-process counterpart of an enrolled agent's
// sendFirewallStatus (internal/agent/agent.go).
func (m *LocalAgentManager) runDrainLoop(ctx context.Context, fst store.AgentStore, collectorID uint) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.drainOnce(fst, collectorID)
			m.reportFirewallStatus(ctx, collectorID)
		}
	}
}

// reportFirewallStatus records the local agent's firewall.Backend
// snapshot straight through collectorService — no HTTP hop, no bearer
// token, mirroring drainOnce above. A stopped agent (m.a == nil, a
// race against Stop between the ticker firing and this running) is a
// silent no-op: nothing to report. Firewall.List failures are logged
// and skipped, same tolerance as internal/agent's sendFirewallStatus.
func (m *LocalAgentManager) reportFirewallStatus(ctx context.Context, collectorID uint) {
	m.mu.Lock()
	a := m.a
	enforcing := m.enforcing
	m.mu.Unlock()
	if a == nil {
		return
	}

	targets, err := a.Firewall.List(ctx)
	if err != nil {
		log.Printf("[local-agent] firewall status: listing %s rules failed: %v", a.Firewall.Name(), err)
		return
	}
	ips := make([]string, 0, len(targets))
	for _, t := range targets {
		ips = append(ips, t.Addr.Addr().String())
	}
	if err := m.collectorService.RecordFirewallStatus(collectorID, a.Firewall.Name(), enforcing, ips); err != nil {
		log.Printf("[local-agent] record firewall status: %v", err)
	}
}

const localAgentDrainBatchSize = 200

func (m *LocalAgentManager) drainOnce(fst store.AgentStore, collectorID uint) {
	obs, err := fst.Dequeue(localAgentDrainBatchSize)
	if err != nil {
		log.Printf("[local-agent] dequeue observations: %v", err)
		return
	}
	if len(obs) == 0 {
		return
	}

	inputs := make([]services.ObservationInput, 0, len(obs))
	ids := make([]string, 0, len(obs))
	for _, o := range obs {
		inputs = append(inputs, services.ObservationInput{
			IP:           o.IP.String(),
			IncidentType: o.Kind,
			HappenedAt:   o.Time,
			Metadata:     localAgentMetadataToAny(o.Metadata),
		})
		ids = append(ids, o.ID)
	}

	if _, err := m.collectorService.CreateIncidentsBatchForCollector(collectorID, inputs); err != nil {
		// Left queued for the next tick's retry — never Ack a batch
		// that wasn't actually persisted.
		log.Printf("[local-agent] persist %d observation(s): %v", len(obs), err)
		return
	}
	if err := fst.Ack(ids); err != nil {
		log.Printf("[local-agent] ack persisted observations: %v", err)
	}
}

func localAgentMetadataToAny(md map[string]string) map[string]interface{} {
	if len(md) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(md))
	for k, v := range md {
		out[k] = v
	}
	return out
}

// unavailableBackend mirrors internal/cli/agent_run.go's stand-in of
// the same name (unexported there, so duplicated rather than shared):
// a dry-run local agent never needs a working firewall.Backend, and
// this only turns into a real error if SetEnforce(true) is later
// requested against it.
type unavailableBackend struct{ err error }

func (u unavailableBackend) Name() string                                     { return "none" }
func (u unavailableBackend) Available(context.Context) error                  { return u.err }
func (u unavailableBackend) Init(context.Context) error                       { return u.err }
func (u unavailableBackend) Flush(context.Context) error                      { return u.err }
func (u unavailableBackend) Block(context.Context, []firewall.Target) error   { return u.err }
func (u unavailableBackend) Unblock(context.Context, []firewall.Target) error { return u.err }
func (u unavailableBackend) List(context.Context) ([]firewall.Target, error)  { return nil, u.err }
