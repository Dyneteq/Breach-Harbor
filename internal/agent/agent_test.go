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

// hasTag reports whether any line in lines has tag as its second
// whitespace-separated field — the live-status log's format is
// "HH:MM:SS <tag>  <message>" (see Agent.emit), and strings.Fields
// collapses the tag column's padding so this is robust to width
// changes there.
func hasTag(lines []string, tag string) bool {
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) >= 2 && fields[1] == tag {
			return true
		}
	}
	return false
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

	if !hasTag(*logs, "would") {
		t.Errorf("expected a 'would' log line once threshold crossed, got logs: %v", *logs)
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

	if !hasTag(*logs, "block") {
		t.Errorf("expected a 'block' log line, got logs: %v", *logs)
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
		if strings.Contains(l, "block failed") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a block-failed log line, got: %v", *logs)
	}
}

func TestAgent_ReconcileState_PicksUpEnforceOnFromDisk(t *testing.T) {
	a, _, fw, logs := newTestAgent(t, false)

	// A separate `agent enforce --on` invocation writes this.
	if err := SaveState(a.Config.DataDir, State{Enforcing: true}); err != nil {
		t.Fatal(err)
	}

	a.reconcileState(context.Background())

	if !a.Config.Enforce {
		t.Error("expected Config.Enforce to flip to true after reconcileState")
	}
	if fw.initCalls != 1 {
		t.Errorf("expected firewall.Init to be called once when turning enforcement on, got %d", fw.initCalls)
	}
	if !hasTag(*logs, "mode") {
		t.Errorf("expected a 'mode' log line announcing enforcement turned on, got: %v", *logs)
	}
}

func TestAgent_ReconcileState_PicksUpEnforceOffFromDisk(t *testing.T) {
	a, _, _, logs := newTestAgent(t, true)

	if err := SaveState(a.Config.DataDir, State{Enforcing: false}); err != nil {
		t.Fatal(err)
	}

	a.reconcileState(context.Background())

	if a.Config.Enforce {
		t.Error("expected Config.Enforce to flip to false after reconcileState")
	}
	if !hasTag(*logs, "mode") {
		t.Errorf("expected a 'mode' log line announcing enforcement turned off, got: %v", *logs)
	}
}

func TestAgent_HandleEvent_EmitsSeenLineForEveryEvent(t *testing.T) {
	a, _, _, logs := newTestAgent(t, false)
	ip := mustAddr(t, "203.0.113.44")

	// Below block-eligible threshold — must still get a "seen" line;
	// "seen" is not gated on the block decision at all.
	a.handleEvent(context.Background(), sshEvent(ip))

	if !hasTag(*logs, "seen") {
		t.Errorf("expected a 'seen' log line for a sub-threshold event, got: %v", *logs)
	}
	found := false
	for _, l := range *logs {
		if strings.Contains(l, ip.String()) && strings.Contains(l, "fails/60s") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the seen line to include the IP and a fails/60s rate, got: %v", *logs)
	}
}

func TestAgent_HandleEvent_SeenLineRateIncreasesWithRepeatedEvents(t *testing.T) {
	a, _, _, logs := newTestAgent(t, false)
	ip := mustAddr(t, "203.0.113.44")

	for i := 0; i < 3; i++ {
		a.handleEvent(context.Background(), sshEvent(ip))
	}

	if !containsSubstring(*logs, "3 fails/60s") {
		t.Errorf("expected the 3rd seen line to report '3 fails/60s', got: %v", *logs)
	}
}

func containsSubstring(lines []string, substr string) bool {
	for _, l := range lines {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

func TestAgent_TotalCounters_TrackSeenFlaggedBlocked(t *testing.T) {
	a, _, _, _ := newTestAgent(t, true)
	ip := mustAddr(t, "203.0.113.44")

	for i := 0; i < 6; i++ { // 6 x +15 = 90 >= threshold 50, crosses once
		a.handleEvent(context.Background(), sshEvent(ip))
	}

	if a.totalSeen != 6 {
		t.Errorf("totalSeen = %d, want 6", a.totalSeen)
	}
	if a.totalFlagged != 1 {
		t.Errorf("totalFlagged = %d, want 1 (only the crossing event, sticky after)", a.totalFlagged)
	}
	if a.totalBlocked != 1 {
		t.Errorf("totalBlocked = %d, want 1", a.totalBlocked)
	}
}

func TestAgent_EmitSummary_ReportsCountsWithThousandsSeparator(t *testing.T) {
	a, _, _, logs := newTestAgent(t, false)
	a.totalSeen = 1284
	a.totalFlagged = 6
	a.totalBlocked = 0

	a.emitSummary(time.Now())

	if !containsSubstring(*logs, "1,284 seen / 6 flagged / 0 blocked") {
		t.Errorf("expected a formatted summary line, got: %v", *logs)
	}
}

func TestFormatCount_ThousandsSeparators(t *testing.T) {
	cases := map[int]string{0: "0", 5: "5", 999: "999", 1000: "1,000", 1284: "1,284", 1234567: "1,234,567", -1234: "-1,234"}
	for n, want := range cases {
		if got := formatCount(n); got != want {
			t.Errorf("formatCount(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestEmitReadyAndMode_DryRun(t *testing.T) {
	a, _, _, logs := newTestAgent(t, false)
	a.Sources = nil // exercise the "no sources detected" branch separately below

	a.emitReadyAndMode(time.Now(), State{DryRunUntil: time.Now().Add(2 * time.Hour)})

	if !hasTag(*logs, "ready") {
		t.Errorf("expected a 'ready' log line, got: %v", *logs)
	}
	if !hasTag(*logs, "mode") {
		t.Errorf("expected a 'mode' log line, got: %v", *logs)
	}
	if !containsSubstring(*logs, "no log sources detected") {
		t.Errorf("expected the ready line to flag zero detected sources, got: %v", *logs)
	}
	if !containsSubstring(*logs, "observe") {
		t.Errorf("expected the mode line to say 'observe' in dry run, got: %v", *logs)
	}
}

func TestEmitReadyAndMode_Enforcing(t *testing.T) {
	a, _, _, logs := newTestAgent(t, true)

	a.emitReadyAndMode(time.Now(), State{})

	if !containsSubstring(*logs, "enforce") {
		t.Errorf("expected the mode line to say 'enforce' when Config.Enforce is true, got: %v", *logs)
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
