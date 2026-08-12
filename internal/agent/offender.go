// Package agent implements the standalone breachharbor agent: it
// turns logsource.Events into scored offenders, persists them via
// internal/store, and drives internal/firewall when enforcing.
package agent

import (
	"net/netip"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/logsource"
)

// ScoreWeights is the fixed-weight rule table that decides how
// suspicious an IP is. There is no statistics and no learning here —
// every number below is a deliberate, documented choice so a user can
// read *why* an IP was flagged (`breachharbor agent top` shows the
// SOURCE column derived from these same reasons).
//
//	Event                                    Weight   Decays?
//	----------------------------------------  -------  --------------------
//	ssh failed login                          +15      yes (sliding window)
//	nginx request to a sensitive path         +10      yes (sliding window)
//	fail2ban already banned this IP           +100     no (instant, trusted)
//	IP falls inside a threat feed range       +100     no (instant, trusted)
//
// Block-eligible threshold: 50. These starting weights are meant to be
// tuned against real logs, per PLAN.md — change them here, in one
// place, and update the comment table above to match.
type ScoreWeights struct {
	SSHFailedLogin int
	HTTPSuspicious int
	Fail2banBan    int
	FeedMatch      int
	// Window is how far back an observation still counts toward the
	// score. Once an event falls out of the window it no longer
	// contributes — that's the entirety of "decay" in M1: a fixed
	// sliding window, not continuous exponential decay. Simpler to
	// reason about, and just as effective at this weight scale.
	Window time.Duration
	// Threshold is the score at which an offender becomes
	// block-eligible (dry run: "would block"; enforcing: blocked).
	Threshold int
}

// DefaultWeights are the starting values documented above.
var DefaultWeights = ScoreWeights{
	SSHFailedLogin: 15,
	HTTPSuspicious: 10,
	Fail2banBan:    100,
	FeedMatch:      100,
	Window:         10 * time.Minute,
	Threshold:      50,
}

// reasonFor returns the short, human-facing label used in
// Offender.Sources and `agent top`'s SOURCE column — independent of
// which concrete logsource.Source produced the event (journal and
// auth.log both report as "ssh").
func reasonFor(kind logsource.EventKind) string {
	switch kind {
	case logsource.EventSSHFailedLogin:
		return "ssh"
	case logsource.EventHTTPSuspicious:
		return "nginx"
	case logsource.EventFail2banBan:
		return "fail2ban"
	default:
		return "unknown"
	}
}

func (w ScoreWeights) weightFor(kind logsource.EventKind) int {
	switch kind {
	case logsource.EventSSHFailedLogin:
		return w.SSHFailedLogin
	case logsource.EventHTTPSuspicious:
		return w.HTTPSuspicious
	case logsource.EventFail2banBan:
		return w.Fail2banBan
	default:
		return 0
	}
}

// scoredEvent is one windowed observation kept in memory per offender
// IP. It is deliberately not persisted as-is — internal/store persists
// the derived Offender/Observation shapes; this is scratch state that
// a restarted agent is allowed to lose (see PLAN.md's M1 design notes).
type scoredEvent struct {
	Time   time.Time
	Weight int
	Reason string // "ssh", "nginx", "fail2ban", or "feed:<provider>"
}

// newObservation converts a raw logsource.Event into a scoredEvent
// using the given weight table.
func newObservation(ev logsource.Event, weights ScoreWeights) scoredEvent {
	return scoredEvent{Time: ev.Time, Weight: weights.weightFor(ev.Kind), Reason: reasonFor(ev.Kind)}
}

// Window holds one IP's recent observations for sliding-window
// scoring. It is not safe for concurrent use — callers (agent.go)
// serialize access per IP.
type Window struct {
	IP     netip.Addr
	Events []scoredEvent
}

// NewWindow returns an empty Window for ip.
func NewWindow(ip netip.Addr) *Window {
	return &Window{IP: ip}
}

// Add appends an event and prunes anything that has fallen out of the
// window.
func (win *Window) Add(now time.Time, weights ScoreWeights, ev scoredEvent) {
	win.Events = append(win.Events, ev)
	win.prune(now, weights.Window)
}

// AddEvent is a convenience wrapper that converts a raw
// logsource.Event before adding it.
func (win *Window) AddEvent(now time.Time, weights ScoreWeights, ev logsource.Event) {
	win.Add(now, weights, newObservation(ev, weights))
}

// ForceFeedMatch records an instant, non-decaying feed hit — the IP
// fell inside a threat-feed-listed range. Unlike ssh/nginx events this
// is trusted outright, matching fail2ban_ban's treatment.
func (win *Window) ForceFeedMatch(now time.Time, weights ScoreWeights, provider string) {
	win.Add(now, weights, scoredEvent{Time: now, Weight: weights.FeedMatch, Reason: "feed:" + provider})
}

func (win *Window) prune(now time.Time, window time.Duration) {
	if window <= 0 {
		return
	}
	cutoff := now.Add(-window)
	i := 0
	for _, e := range win.Events {
		if e.Time.After(cutoff) {
			win.Events[i] = e
			i++
		}
	}
	win.Events = win.Events[:i]
}

// Score returns the sum of every still-in-window event's weight,
// after pruning anything that has aged out.
func (win *Window) Score(now time.Time, weights ScoreWeights) int {
	win.prune(now, weights.Window)
	score := 0
	for _, e := range win.Events {
		score += e.Weight
	}
	return score
}

// BlockEligible reports whether this window's current score meets or
// exceeds the block-eligible threshold.
func (win *Window) BlockEligible(now time.Time, weights ScoreWeights) bool {
	return win.Score(now, weights) >= weights.Threshold
}

// countInLast counts this window's still-tracked events matching
// reason that happened within the last d — a display-only figure
// (the live status log's "N fails/60s"), independent of Score's own
// decay window (Weights.Window, 10 minutes by default).
func (win *Window) countInLast(now time.Time, reason string, d time.Duration) int {
	cutoff := now.Add(-d)
	n := 0
	for _, e := range win.Events {
		if e.Reason == reason && e.Time.After(cutoff) {
			n++
		}
	}
	return n
}

// Sources returns the deduped set of reasons behind this window's
// events, in first-seen order, e.g. ["ssh", "feed:spamhaus"].
func (win *Window) Sources() []string {
	seen := make(map[string]bool, len(win.Events))
	var out []string
	for _, e := range win.Events {
		if seen[e.Reason] {
			continue
		}
		seen[e.Reason] = true
		out = append(out, e.Reason)
	}
	return out
}
