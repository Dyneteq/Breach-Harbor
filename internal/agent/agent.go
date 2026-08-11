package agent

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/feed"
	"github.com/Dyneteq/Breach-Harbor/internal/firewall"
	"github.com/Dyneteq/Breach-Harbor/internal/logsource"
	"github.com/Dyneteq/Breach-Harbor/internal/store"
)

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

	// Logf is where the scrolling console log goes. Defaults to
	// stdout; tests substitute something that just records lines.
	Logf func(format string, args ...any)

	// windows is loop-local: only Run's goroutine ever touches it, so
	// it needs no lock (handleEvent is called synchronously from
	// Run's single select loop, never concurrently).
	windows map[string]*Window

	feedMu      sync.RWMutex
	feedEntries []feed.Entry
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

	events := make(chan logsource.Event, 256)
	var wg sync.WaitGroup
	for _, src := range a.Sources {
		wg.Add(1)
		go func(s logsource.Source) {
			defer wg.Done()
			if err := s.Watch(ctx, events); err != nil && ctx.Err() == nil {
				a.Logf("[%s] source %s stopped: %v", ts(time.Now()), s.Name(), err)
			}
		}(src)
	}

	refresh := a.Config.Refresh
	if refresh <= 0 {
		refresh = 15 * time.Minute
	}
	ticker := time.NewTicker(refresh)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		case ev := <-events:
			a.handleEvent(ctx, ev)
		case <-ticker.C:
			go a.refreshFeeds(ctx)
		}
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
			a.Logf("[%s] feed %s: %v", ts(time.Now()), p.Name(), err)
			continue
		}
		merged = append(merged, entries...)
		summaries = append(summaries, fmt.Sprintf("%s (%d entries)", p.Name(), len(entries)))
	}

	a.feedMu.Lock()
	a.feedEntries = merged
	a.feedMu.Unlock()

	if len(summaries) > 0 {
		a.Logf("[%s] feeds: %s", ts(time.Now()), strings.Join(summaries, ", "))
	}
}

// feedMatch reports the provider name of the first cached feed entry
// whose range contains ip, if any.
func (a *Agent) feedMatch(ip netip.Addr) (string, bool) {
	a.feedMu.RLock()
	defer a.feedMu.RUnlock()
	for _, e := range a.feedEntries {
		if e.Prefix.Contains(ip) {
			return e.Provider, true
		}
	}
	return "", false
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
		a.Logf("[%s] store error for %s: %v", ts(now), ev.IP, err)
	}
	offender := store.Offender{
		IP:        ev.IP,
		Score:     win.Score(now, a.Weights),
		Events:    existing.Events + 1,
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
		a.block(ctx, &offender, win, ev, now)
	}

	if err := a.Store.PutOffender(offender); err != nil {
		a.Logf("[%s] failed to persist offender %s: %v", ts(now), ev.IP, err)
	}
}

func (a *Agent) block(ctx context.Context, offender *store.Offender, win *Window, ev logsource.Event, now time.Time) {
	reason := summarize(win, now, a.Weights)
	if !a.Config.Enforce {
		a.Logf("[%s] WOULD BLOCK  %-15s %s: %s", ts(now), ev.IP, ev.Source, reason)
		return
	}
	target := firewall.Target{Addr: netip.PrefixFrom(ev.IP, ev.IP.BitLen())}
	if err := a.Firewall.Block(ctx, []firewall.Target{target}); err != nil {
		a.Logf("[%s] BLOCK FAILED %-15s %v", ts(now), ev.IP, err)
		return
	}
	blockedAt := now
	offender.Blocked = true
	offender.BlockedAt = &blockedAt
	a.Logf("[%s] BLOCKED      %-15s %s: %s", ts(now), ev.IP, ev.Source, reason)
}

// summarize is the human-readable "why" behind a block decision —
// the SOURCE + score PLAN.md asks every flagged IP to be explainable
// by (see offender.go's weight table comment).
func summarize(win *Window, now time.Time, weights ScoreWeights) string {
	return fmt.Sprintf("%s (score %d, threshold %d)", strings.Join(win.Sources(), ", "), win.Score(now, weights), weights.Threshold)
}

func ts(t time.Time) string { return t.Format("2006-01-02 15:04:05") }
