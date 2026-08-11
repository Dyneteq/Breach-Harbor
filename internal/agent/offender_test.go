package agent

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/logsource"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("invalid address %q: %v", s, err)
	}
	return a
}

func TestWindow_SingleSSHEvent_NotYetEligible(t *testing.T) {
	now := time.Now()
	win := NewWindow(mustAddr(t, "203.0.113.44"))
	win.AddEvent(now, DefaultWeights, logsource.Event{Kind: logsource.EventSSHFailedLogin, Time: now})

	if got, want := win.Score(now, DefaultWeights), 15; got != want {
		t.Errorf("Score = %d, want %d", got, want)
	}
	if win.BlockEligible(now, DefaultWeights) {
		t.Error("expected a single ssh event not to be block-eligible")
	}
}

func TestWindow_RepeatedSSHEvents_CrossThreshold(t *testing.T) {
	now := time.Now()
	win := NewWindow(mustAddr(t, "203.0.113.44"))
	// 4 x +15 = 60 >= threshold 50.
	for i := 0; i < 4; i++ {
		win.AddEvent(now, DefaultWeights, logsource.Event{Kind: logsource.EventSSHFailedLogin, Time: now})
	}
	if got, want := win.Score(now, DefaultWeights), 60; got != want {
		t.Errorf("Score = %d, want %d", got, want)
	}
	if !win.BlockEligible(now, DefaultWeights) {
		t.Error("expected 4 ssh events (score 60) to be block-eligible at threshold 50")
	}
	if got := win.Sources(); len(got) != 1 || got[0] != "ssh" {
		t.Errorf("Sources = %v, want [ssh]", got)
	}
}

func TestWindow_EventsOutsideWindow_DoNotCount(t *testing.T) {
	now := time.Now()
	win := NewWindow(mustAddr(t, "203.0.113.44"))
	old := now.Add(-DefaultWeights.Window - time.Minute)
	win.AddEvent(now, DefaultWeights, logsource.Event{Kind: logsource.EventSSHFailedLogin, Time: old})

	if got, want := win.Score(now, DefaultWeights), 0; got != want {
		t.Errorf("Score = %d, want %d (event should have aged out of the window)", got, want)
	}
}

func TestWindow_AgingPrunesOldEvents(t *testing.T) {
	weights := DefaultWeights
	weights.Window = 10 * time.Minute
	base := time.Now()

	win := NewWindow(mustAddr(t, "203.0.113.44"))
	win.AddEvent(base, weights, logsource.Event{Kind: logsource.EventSSHFailedLogin, Time: base})
	if got := win.Score(base, weights); got != 15 {
		t.Fatalf("Score at t0 = %d, want 15", got)
	}

	later := base.Add(11 * time.Minute)
	if got := win.Score(later, weights); got != 0 {
		t.Errorf("Score after the window elapsed = %d, want 0", got)
	}
}

func TestWindow_HTTPBurst_AccumulatesToThreshold(t *testing.T) {
	now := time.Now()
	win := NewWindow(mustAddr(t, "192.0.2.187"))
	// 5 x +10 = 50 >= threshold 50.
	for i := 0; i < 5; i++ {
		win.AddEvent(now, DefaultWeights, logsource.Event{Kind: logsource.EventHTTPSuspicious, Time: now})
	}
	if !win.BlockEligible(now, DefaultWeights) {
		t.Error("expected 5 nginx events (score 50) to be block-eligible at threshold 50")
	}
}

func TestWindow_Fail2banBan_InstantlyEligible(t *testing.T) {
	now := time.Now()
	win := NewWindow(mustAddr(t, "198.51.100.9"))
	win.AddEvent(now, DefaultWeights, logsource.Event{Kind: logsource.EventFail2banBan, Time: now})
	if !win.BlockEligible(now, DefaultWeights) {
		t.Error("expected a single fail2ban ban line to be instantly block-eligible")
	}
	if got := win.Sources(); len(got) != 1 || got[0] != "fail2ban" {
		t.Errorf("Sources = %v, want [fail2ban]", got)
	}
}

func TestWindow_ForceFeedMatch_InstantlyEligibleAndTagged(t *testing.T) {
	now := time.Now()
	win := NewWindow(mustAddr(t, "198.51.100.9"))
	// A single sub-threshold ssh event first...
	win.AddEvent(now, DefaultWeights, logsource.Event{Kind: logsource.EventSSHFailedLogin, Time: now})
	if win.BlockEligible(now, DefaultWeights) {
		t.Fatal("precondition: single ssh event should not yet be eligible")
	}
	// ...then a feed match forces it over the threshold immediately.
	win.ForceFeedMatch(now, DefaultWeights, "spamhaus")
	if !win.BlockEligible(now, DefaultWeights) {
		t.Error("expected a feed match to be instantly block-eligible")
	}
	got := win.Sources()
	if len(got) != 2 || got[0] != "ssh" || got[1] != "feed:spamhaus" {
		t.Errorf("Sources = %v, want [ssh feed:spamhaus]", got)
	}
}

func TestWindow_SourcesDeduplicates(t *testing.T) {
	now := time.Now()
	win := NewWindow(mustAddr(t, "203.0.113.44"))
	for i := 0; i < 3; i++ {
		win.AddEvent(now, DefaultWeights, logsource.Event{Kind: logsource.EventSSHFailedLogin, Time: now})
	}
	if got := win.Sources(); len(got) != 1 {
		t.Errorf("Sources = %v, want exactly one deduplicated entry", got)
	}
}

func TestReasonFor_UnknownKindIsLabeled(t *testing.T) {
	if got := reasonFor(logsource.EventKind("bogus")); got != "unknown" {
		t.Errorf("reasonFor(bogus) = %q, want %q", got, "unknown")
	}
}
