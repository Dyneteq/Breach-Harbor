package agent

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/blocklist"
	"github.com/Dyneteq/Breach-Harbor/internal/feed"
	"github.com/Dyneteq/Breach-Harbor/internal/firewall"
	"github.com/Dyneteq/Breach-Harbor/internal/logsource"
	"github.com/Dyneteq/Breach-Harbor/internal/store"
)

// summaryInterval is how often Run emits a "summary" line — a fixed
// heartbeat cadence distinct from the feed/upload ticker (Config.Refresh,
// default 15m, far too infrequent for a live-status view) and the
// 3s state-reconcile ticker (far too chatty for a summary).
const summaryInterval = 2 * time.Minute

// Agent wires everything together: logsource.Sources feed Events into
// a per-IP sliding-window score (offender.go), scored offenders are
// persisted via store.AgentStore, and a threshold crossing either logs
// "would block" (dry run) or calls firewall.Backend.Block (enforcing).
type Agent struct {
	Config   Config
	Store    store.AgentStore
	Firewall firewall.Backend
	Feeds    []feed.Provider
	Sources  []logsource.Source
	Weights  ScoreWeights

	// Uploader is nil for a standalone agent (the default). When set
	// (internal/cli/agent_run.go, once `agent enroll` has persisted an
	// Enrollment), Run periodically drains the observation queue to
	// the server and merges its published blocklist into detection —
	// PLAN.md M2 item 7.
	Uploader *Uploader

	// Logf is where the scrolling console log goes. Defaults to
	// stdout; tests substitute something that just records lines.
	Logf func(format string, args ...any)

	// windows is loop-local: only Run's goroutine ever touches it, so
	// it needs no lock (handleEvent is called synchronously from
	// Run's single select loop, never concurrently).
	windows map[string]*Window

	// totalSeen/totalFlagged/totalBlocked back the periodic "summary"
	// line. Loop-local like windows above — only handleEvent/block and
	// the summary ticker (both driven from Run's single select loop)
	// ever touch them.
	totalSeen    int
	totalFlagged int
	totalBlocked int

	feedMu           sync.RWMutex
	feedEntries      []feed.Entry
	blocklistEntries []feed.Entry
}

// New returns an Agent ready to Run. cfg should already be validated
// (Config.Validate) by the caller.
func New(cfg Config, st store.AgentStore, fw firewall.Backend, feeds []feed.Provider, sources []logsource.Source) *Agent {
	return &Agent{
		Config:   cfg,
		Store:    st,
		Firewall: fw,
		Feeds:    feeds,
		Sources:  sources,
		Weights:  DefaultWeights,
		Logf:     func(format string, args ...any) { fmt.Printf(format+"\n", args...) },
		windows:  make(map[string]*Window),
	}
}

// Run watches every source and scores observations until ctx is
// cancelled. It never returns an error just because a source or feed
// is unavailable — those are logged and the agent keeps going with
// whatever it does have.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.Config.Validate(); err != nil {
		return err
	}

	state, err := LoadState(a.Config.DataDir)
	if err != nil {
		return err
	}

	if a.Config.Enforce {
		if err := a.Firewall.Init(ctx); err != nil {
			return fmt.Errorf("firewall init: %w", err)
		}
		if !state.Enforcing {
			now := time.Now()
			state.Enforcing = true
			state.EnforcingSince = &now
		}
	}
	state.PID = os.Getpid()
	if err := SaveState(a.Config.DataDir, state); err != nil {
		return err
	}

	// Load feeds once synchronously before entering the loop so the
	// very first observations can already be feed-checked, matching
	// PLAN.md's demo transcript (feeds print before any WOULD BLOCK
	// line).
	a.refreshFeeds(ctx)
	if a.Uploader != nil {
		a.syncEnrollment(ctx)
	}

	events := make(chan logsource.Event, 256)
	var wg sync.WaitGroup
	for _, src := range a.Sources {
		wg.Add(1)
		go func(s logsource.Source) {
			defer wg.Done()
			if err := s.Watch(ctx, events); err != nil && ctx.Err() == nil {
				a.emit(time.Now(), "warn", "source %s stopped: %v", s.Name(), err)
			}
		}(src)
	}

	a.emitReadyAndMode(time.Now(), state)

	refresh := a.Config.Refresh
	if refresh <= 0 {
		refresh = 15 * time.Minute
	}
	ticker := time.NewTicker(refresh)
	defer ticker.Stop()

	// stateTicker lets a separate `breachharbor agent enforce --on/--off`
	// invocation actually change this live process's behavior — Run
	// only reads Config.Enforce once at startup otherwise, so without
	// this a running agent would never notice enforce was toggled
	// short of a restart.
	stateTicker := time.NewTicker(3 * time.Second)
	defer stateTicker.Stop()

	// summaryTicker drives the periodic "summary" line — see
	// summaryInterval's doc comment for why it's its own ticker rather
	// than reusing one of the two above.
	summaryTicker := time.NewTicker(summaryInterval)
	defer summaryTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			// One last summary on a clean shutdown, so even a short
			// dev/test run shows a final tally instead of cutting off
			// mid-stream — skipped entirely if nothing was ever seen,
			// so a Ctrl+C two seconds after startup doesn't print a
			// pointless "0 seen / 0 flagged / 0 blocked".
			if a.totalSeen > 0 {
				a.emitSummary(time.Now())
			}
			return nil
		case ev := <-events:
			a.handleEvent(ctx, ev)
		case <-ticker.C:
			go a.refreshFeeds(ctx)
			if a.Uploader != nil {
				go a.syncEnrollment(ctx)
			}
		case <-stateTicker.C:
			a.reconcileState(ctx)
		case <-summaryTicker.C:
			a.emitSummary(time.Now())
		}
	}
}

// emitReadyAndMode prints the two lines that open the marketing
// site's terminal demo (index.html): what's being tailed, and
// whether the agent is observing or enforcing right now.
func (a *Agent) emitReadyAndMode(now time.Time, state State) {
	if len(a.Sources) == 0 {
		a.emit(now, "ready", "no log sources detected — running with zero visibility")
	} else {
		names := make([]string, 0, len(a.Sources))
		for _, s := range a.Sources {
			names = append(names, s.Name())
		}
		a.emit(now, "ready", "tailing %s", strings.Join(names, ", "))
	}

	if a.Config.Enforce {
		a.emit(now, "mode", "enforce · blocking live")
		return
	}
	remaining := time.Until(state.DryRunUntil)
	if remaining > 0 {
		a.emit(now, "mode", "observe · %s to enforcement", formatDuration(remaining))
	} else {
		a.emit(now, "mode", "observe · dry run window elapsed, still not enforcing (run `breachharbor agent enforce --on`)")
	}
}

// emitSummary prints the periodic running-totals line.
func (a *Agent) emitSummary(now time.Time) {
	a.emit(now, "summary", "%s seen / %s flagged / %s blocked", formatCount(a.totalSeen), formatCount(a.totalFlagged), formatCount(a.totalBlocked))
}

// reconcileState re-reads the persisted State and applies any
// enforce-mode change made by a separate `agent enforce` invocation
// since the last check.
func (a *Agent) reconcileState(ctx context.Context) {
	state, err := LoadState(a.Config.DataDir)
	if err != nil {
		return
	}
	switch {
	case state.Enforcing && !a.Config.Enforce:
		if err := a.Firewall.Init(ctx); err != nil {
			a.emit(time.Now(), "error", "enforce --on requested but firewall init failed: %v", err)
			return
		}
		a.Config.Enforce = true
		a.emit(time.Now(), "mode", "enforce · blocking live (agent enforce --on)")
	case !state.Enforcing && a.Config.Enforce:
		a.Config.Enforce = false
		a.emit(time.Now(), "mode", "observe · enforcement turned off (agent enforce --off) — already-blocked IPs remain blocked, run `agent flush` to remove them")
	}
}

// refreshFeeds re-fetches every configured, key-satisfied feed
// provider and replaces the in-memory union used by feedMatch. Each
// provider is expected to be wrapped in a feed.CachedProvider by the
// caller, so a network failure here still serves a last-good cache
// rather than losing coverage.
func (a *Agent) refreshFeeds(ctx context.Context) {
	var merged []feed.Entry
	var summaries []string
	for _, p := range a.Feeds {
		if needed, configured := p.RequiresKey(); needed && !configured {
			continue
		}
		if !a.Config.FeedEnabled(p.Name()) {
			continue
		}
		entries, err := p.Fetch(ctx)
		if err != nil {
			a.emit(time.Now(), "warn", "feed %s: %v", p.Name(), err)
			continue
		}
		merged = append(merged, entries...)
		summaries = append(summaries, fmt.Sprintf("%s (%d entries)", p.Name(), len(entries)))
	}

	a.feedMu.Lock()
	a.feedEntries = merged
	a.feedMu.Unlock()

	if len(summaries) > 0 {
		a.emit(time.Now(), "feeds", "%s", strings.Join(summaries, ", "))
	}
}

// feedMatch reports the provider name of the first cached feed entry
// (local providers, or — once enrolled — the server's published
// blocklist) whose range contains ip, if any.
func (a *Agent) feedMatch(ip netip.Addr) (string, bool) {
	a.feedMu.RLock()
	defer a.feedMu.RUnlock()
	for _, e := range a.feedEntries {
		if e.Prefix.Contains(ip) {
			return e.Provider, true
		}
	}
	for _, e := range a.blocklistEntries {
		if e.Prefix.Contains(ip) {
			return e.Provider, true
		}
	}
	return "", false
}

// syncEnrollment drains the local observation queue to the enrolled
// server and refreshes the merged blocklist used by feedMatch above.
// A failure in either half is logged and never fatal — an enrolled
// agent that temporarily can't reach its server keeps operating on
// local detection alone (PLAN.md's "cache first, ask later").
func (a *Agent) syncEnrollment(ctx context.Context) {
	if n, err := a.Uploader.UploadPending(ctx); err != nil {
		a.emit(time.Now(), "sync", "upload to %s failed (will retry): %v", a.Uploader.Enrollment.ServerURL, err)
	} else if n > 0 {
		a.emit(time.Now(), "sync", "uploaded %d observation(s) to %s", n, a.Uploader.Enrollment.ServerURL)
	}

	a.feedMu.RLock()
	local := make([]blocklist.Entry, 0, len(a.feedEntries))
	for _, e := range a.feedEntries {
		local = append(local, blocklist.Entry{Prefix: e.Prefix, Reason: e.Provider + ": " + e.Reason})
	}
	a.feedMu.RUnlock()

	merged, err := a.Uploader.RefreshBlocklist(ctx, local)
	if err != nil {
		a.emit(time.Now(), "warn", "blocklist refresh: %v", err)
	}

	entries := make([]feed.Entry, 0, len(merged))
	for _, e := range merged {
		entries = append(entries, feed.Entry{Prefix: e.Prefix, Reason: e.Reason, Provider: "blocklist"})
	}
	a.feedMu.Lock()
	a.blocklistEntries = entries
	a.feedMu.Unlock()
}

// handleEvent scores one observation, persists the resulting
// Offender, and — the moment an offender first crosses the
// block-eligible threshold — either logs "would block" (dry run) or
// blocks it for real (enforcing).
func (a *Agent) handleEvent(ctx context.Context, ev logsource.Event) {
	now := time.Now()
	if ev.Time.IsZero() {
		ev.Time = now
	}
	a.totalSeen++

	// Queued regardless of enrollment status — a standalone agent's
	// queue just never drains (store.Observation's doc comment), but an
	// agent enrolled later (internal/agent/enroll.go, M2) needs
	// something for its uploader to have already been collecting.
	if err := a.Store.Enqueue(store.Observation{
		IP:       ev.IP,
		Kind:     string(ev.Kind),
		Time:     ev.Time,
		Metadata: map[string]string{"source": ev.Source},
	}); err != nil {
		a.emit(now, "error", "failed to enqueue observation for %s: %v", ev.IP, err)
	}

	win := a.windows[ev.IP.String()]
	if win == nil {
		win = NewWindow(ev.IP)
		a.windows[ev.IP.String()] = win
	}
	wasEligible := win.BlockEligible(now, a.Weights)
	win.AddEvent(now, a.Weights, ev)
	if provider, ok := a.feedMatch(ev.IP); ok {
		win.ForceFeedMatch(now, a.Weights, provider)
	}
	nowEligible := win.BlockEligible(now, a.Weights)

	existing, found, err := a.Store.GetOffender(ev.IP)
	if err != nil {
		a.emit(now, "error", "store error for %s: %v", ev.IP, err)
	}
	lifetimeEvents := existing.Events + 1

	a.emit(now, "seen", "%-15s %-8s %s", ev.IP, reasonFor(ev.Kind), seenDetail(win, ev, lifetimeEvents, now))

	offender := store.Offender{
		IP:        ev.IP,
		Score:     win.Score(now, a.Weights),
		Events:    lifetimeEvents,
		FirstSeen: existing.FirstSeen,
		LastSeen:  now,
		Sources:   win.Sources(),
		Blocked:   existing.Blocked,
		BlockedAt: existing.BlockedAt,
	}
	if !found || offender.FirstSeen.IsZero() {
		offender.FirstSeen = now
	}

	// Sticky blocking: once Blocked=true, only `agent flush` (removes
	// the real firewall rule) changes that — a windowed score dipping
	// back under threshold later never auto-unblocks.
	if nowEligible && !wasEligible && !offender.Blocked {
		a.totalFlagged++
		a.block(ctx, &offender, win, ev, now)
	}

	if err := a.Store.PutOffender(offender); err != nil {
		a.emit(now, "error", "failed to persist offender %s: %v", ev.IP, err)
	}
}

func (a *Agent) block(ctx context.Context, offender *store.Offender, win *Window, ev logsource.Event, now time.Time) {
	reason := summarize(win, now, a.Weights)
	if !a.Config.Enforce {
		a.emit(now, "would", "block %-15s (%s)", ev.IP, reason)
		return
	}
	target := firewall.Target{Addr: netip.PrefixFrom(ev.IP, ev.IP.BitLen())}
	if err := a.Firewall.Block(ctx, []firewall.Target{target}); err != nil {
		a.emit(now, "error", "block failed for %-15s %v", ev.IP, err)
		return
	}
	blockedAt := now
	offender.Blocked = true
	offender.BlockedAt = &blockedAt
	a.totalBlocked++
	a.emit(now, "block", "%-15s (%s)", ev.IP, reason)
}

// summarize is the human-readable "why" behind a block decision —
// the SOURCE + score PLAN.md asks every flagged IP to be explainable
// by (see offender.go's weight table comment).
func summarize(win *Window, now time.Time, weights ScoreWeights) string {
	return fmt.Sprintf("%s (score %d, threshold %d)", strings.Join(win.Sources(), ", "), win.Score(now, weights), weights.Threshold)
}

// emit writes one line of the agent's live status log — HH:MM:SS, a
// left-aligned tag, then a free-form message. This is the format
// demoed on the marketing site's terminal animation (index.html):
// every scrolling line the agent prints, from startup through every
// observation and block decision, goes through this one function.
func (a *Agent) emit(now time.Time, tag, format string, args ...any) {
	a.Logf("%s %-7s %s", now.Format("15:04:05"), tag, fmt.Sprintf(format, args...))
}

// formatCount renders n with thousands separators, e.g. 1284 ->
// "1,284" — matches the summary line's style in the marketing site's
// terminal demo. Hand-rolled rather than pulling in
// golang.org/x/text/message for one integer format.
func formatCount(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var parts []string
	for len(s) > 3 {
		parts = append([]string{s[len(s)-3:]}, parts...)
		s = s[:len(s)-3]
	}
	parts = append([]string{s}, parts...)
	out := strings.Join(parts, ",")
	if neg {
		out = "-" + out
	}
	return out
}

// formatDuration renders a duration the way the "mode" line's time-to-
// enforcement figure does: "23h58m" / "3h12m" / "46s" — coarser than
// time.Duration.String(), no sub-second noise. Duplicated from
// internal/cli/output.go's identical helper rather than shared across
// the package boundary — see internal/agent/systemd.go's doc comment
// on this repo's convention of small, deliberate duplication over
// cross-package coupling for a function this size.
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	switch {
	case h > 0:
		return fmt.Sprintf("%dh%dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm%ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

// seenDetail is the third column of a "seen" line — a short,
// kind-specific description of what was just observed.
func seenDetail(win *Window, ev logsource.Event, lifetimeCount int, now time.Time) string {
	switch ev.Kind {
	case logsource.EventSSHFailedLogin:
		return fmt.Sprintf("%d fails/60s", win.countInLast(now, reasonFor(ev.Kind), 60*time.Second))
	case logsource.EventHTTPSuspicious:
		return fmt.Sprintf("sweep ×%d", lifetimeCount)
	case logsource.EventFail2banBan:
		return "already banned by fail2ban"
	default:
		return "observed"
	}
}
