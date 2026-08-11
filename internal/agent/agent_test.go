package agent

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/feed"
	"github.com/Dyneteq/Breach-Harbor/internal/firewall"
	"github.com/Dyneteq/Breach-Harbor/internal/logsource"
	"github.com/Dyneteq/Breach-Harbor/internal/store"
)

// fakeBackend records firewall calls without touching a real nft/
// iptables binary.
type fakeBackend struct {
	initCalls    int
	blockCalls   int
	unblockCalls int
	blocked      []firewall.Target
	blockErr     error
}

func (f *fakeBackend) Name() string                                        { return "fake" }
func (f *fakeBackend) Available(ctx context.Context) error                 { return nil }
func (f *fakeBackend) Init(ctx context.Context) error                      { f.initCalls++; return nil }
func (f *fakeBackend) List(ctx context.Context) ([]firewall.Target, error) { return f.blocked, nil }
func (f *fakeBackend) Flush(ctx context.Context) error                     { return nil }
func (f *fakeBackend) Unblock(ctx context.Context, targets []firewall.Target) error {
	f.unblockCalls++
	return nil
}
func (f *fakeBackend) Block(ctx context.Context, targets []firewall.Target) error {
	f.blockCalls++
	f.blocked = append(f.blocked, targets...)
	return f.blockErr
}

func newTestAgent(t *testing.T, enforce bool) (*Agent, *store.FileStore, *fakeBackend, *[]string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	fw := &fakeBackend{}
	cfg := Default()
	cfg.DataDir = dir
	cfg.Enforce = enforce

	a := New(cfg, st, fw, nil, nil)
	var logs []string
	a.Logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
	return a, st, fw, &logs
}

func sshEvent(ip netip.Addr) logsource.Event {
	return logsource.Event{Source: "auth.log", Kind: logsource.EventSSHFailedLogin, IP: ip, Time: time.Now()}
}

func TestAgent_DryRun_LogsWouldBlockOnThresholdCross_NeverTouchesFirewall(t *testing.T) {
	a, st, fw, logs := newTestAgent(t, false)
	ip := mustAddr(t, "203.0.113.44")

	// 4 x +15 = 60 >= threshold 50.
	for i := 0; i < 4; i++ {
		a.handleEvent(context.Background(), sshEvent(ip))
	}

	off, ok, err := st.GetOffender(ip)
	if err != nil || !ok {
		t.Fatalf("expected offender to be persisted, ok=%v err=%v", ok, err)
	}
	if off.Blocked {
		t.Error("dry run must never set Blocked=true")
	}
	if off.Events != 4 {
		t.Errorf("Events = %d, want 4", off.Events)
	}
	if fw.blockCalls != 0 {
		t.Errorf("dry run must never call firewall.Block, got %d calls", fw.blockCalls)
	}

	found := false
	for _, l := range *logs {
		if strings.Contains(l, "WOULD BLOCK") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a WOULD BLOCK log line once threshold crossed, got logs: %v", *logs)
	}
}

func TestAgent_Enforcing_BlocksOnThresholdCross_ExactlyOnce(t *testing.T) {
	a, st, fw, logs := newTestAgent(t, true)
	ip := mustAddr(t, "203.0.113.44")

	for i := 0; i < 6; i++ {
		a.handleEvent(context.Background(), sshEvent(ip))
	}

	off, ok, err := st.GetOffender(ip)
	if err != nil || !ok {
		t.Fatalf("expected offender to be persisted, ok=%v err=%v", ok, err)
	}
	if !off.Blocked {
		t.Error("expected Blocked=true after enforcing crossed the threshold")
	}
	if off.BlockedAt == nil {
		t.Error("expected BlockedAt to be set")
	}
	if fw.blockCalls != 1 {
		t.Errorf("expected exactly 1 firewall.Block call (sticky — no re-block on later events), got %d", fw.blockCalls)
	}

	found := false
	for _, l := range *logs {
		if strings.Contains(l, "BLOCKED") && !strings.Contains(l, "FAILED") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a BLOCKED log line, got logs: %v", *logs)
	}
}

func TestAgent_SubThresholdEvents_NeverBlock(t *testing.T) {
	a, st, fw, _ := newTestAgent(t, true)
	ip := mustAddr(t, "203.0.113.44")

	a.handleEvent(context.Background(), sshEvent(ip)) // single event, score 15 < 50

	off, ok, _ := st.GetOffender(ip)
	if !ok {
		t.Fatal("expected the offender to still be tracked")
	}
	if off.Blocked {
		t.Error("expected a single sub-threshold event not to trigger a block")
	}
	if fw.blockCalls != 0 {
		t.Errorf("expected 0 firewall.Block calls, got %d", fw.blockCalls)
	}
}

func TestAgent_FeedMatch_InstantlyBlockEligible(t *testing.T) {
	a, st, fw, _ := newTestAgent(t, true)
	ip := mustAddr(t, "198.51.100.9")
	rangePrefix, err := netip.ParsePrefix("198.51.100.0/24")
	if err != nil {
		t.Fatal(err)
	}
	a.feedEntries = []feed.Entry{{Prefix: rangePrefix, Provider: "spamhaus", Reason: "spamhaus DROP"}}

	// A single ssh event (score 15 alone) should be forced over
	// threshold by the feed match on the very first observation.
	a.handleEvent(context.Background(), sshEvent(ip))

	if fw.blockCalls != 1 {
		t.Errorf("expected the feed match to make a single sub-threshold event instantly block-eligible, got %d Block calls", fw.blockCalls)
	}
	off, _, _ := st.GetOffender(ip)
	found := false
	for _, s := range off.Sources {
		if s == "feed:spamhaus" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Sources to include feed:spamhaus, got %v", off.Sources)
	}
}

func TestAgent_BlockFailure_DoesNotMarkBlocked(t *testing.T) {
	a, st, fw, logs := newTestAgent(t, true)
	fw.blockErr = fmt.Errorf("permission denied")
	ip := mustAddr(t, "203.0.113.44")

	for i := 0; i < 4; i++ {
		a.handleEvent(context.Background(), sshEvent(ip))
	}

	off, _, _ := st.GetOffender(ip)
	if off.Blocked {
		t.Error("a failed firewall.Block must not be recorded as Blocked=true")
	}
	found := false
	for _, l := range *logs {
		if strings.Contains(l, "BLOCK FAILED") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a BLOCK FAILED log line, got: %v", *logs)
	}
}

func TestState_LoadState_FreshDataDir_DefaultsTo24hDryRun(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Enforcing {
		t.Error("expected a fresh state to start not-enforcing")
	}
	gotDuration := s.DryRunUntil.Sub(s.StartedAt)
	if gotDuration < DefaultDryRunDuration-time.Second || gotDuration > DefaultDryRunDuration+time.Second {
		t.Errorf("DryRunUntil - StartedAt = %s, want ~%s", gotDuration, DefaultDryRunDuration)
	}
}

func TestState_SaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Truncate(time.Second)
	want := State{StartedAt: now, DryRunUntil: now.Add(time.Hour), Enforcing: true, EnforcingSince: &now, PID: 1234}
	if err := SaveState(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enforcing || got.PID != 1234 {
		t.Errorf("got %+v, want Enforcing=true PID=1234", got)
	}
	if got.EnforcingSince == nil || !got.EnforcingSince.Equal(now) {
		t.Errorf("EnforcingSince = %v, want %v", got.EnforcingSince, now)
	}
}
