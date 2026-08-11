package store

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("invalid address %q: %v", s, err)
	}
	return a
}

func TestFileStore_OffenderRoundTrip(t *testing.T) {
	dir := t.TempDir()
	fs, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	ip := mustAddr(t, "203.0.113.44")
	now := time.Now().Truncate(time.Second)
	o := Offender{IP: ip, Score: 60, Events: 4, FirstSeen: now, LastSeen: now, Sources: []string{"ssh"}}
	if err := fs.PutOffender(o); err != nil {
		t.Fatal(err)
	}

	got, ok, err := fs.GetOffender(ip)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected offender to be found")
	}
	if got.Score != 60 || got.Events != 4 {
		t.Errorf("got %+v, want Score=60 Events=4", got)
	}

	// Reopening the store (simulating a restart) must see the same state.
	fs.Close()
	fs2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fs2.Close()

	got2, ok, err := fs2.GetOffender(ip)
	if err != nil || !ok {
		t.Fatalf("expected offender to survive reopen, ok=%v err=%v", ok, err)
	}
	if got2.Score != 60 || len(got2.Sources) != 1 || got2.Sources[0] != "ssh" {
		t.Errorf("got %+v after reopen, want Score=60 Sources=[ssh]", got2)
	}
}

func TestFileStore_ListOffenders_SortedByScoreDescending(t *testing.T) {
	dir := t.TempDir()
	fs, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	_ = fs.PutOffender(Offender{IP: mustAddr(t, "203.0.113.1"), Score: 10})
	_ = fs.PutOffender(Offender{IP: mustAddr(t, "203.0.113.2"), Score: 90})
	_ = fs.PutOffender(Offender{IP: mustAddr(t, "203.0.113.3"), Score: 50})

	list, err := fs.ListOffenders()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("got %d offenders, want 3", len(list))
	}
	if list[0].Score != 90 || list[1].Score != 50 || list[2].Score != 10 {
		t.Errorf("scores in order = %d, %d, %d — want 90, 50, 10", list[0].Score, list[1].Score, list[2].Score)
	}
}

func TestFileStore_DeleteOffender(t *testing.T) {
	dir := t.TempDir()
	fs, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	ip := mustAddr(t, "203.0.113.44")
	_ = fs.PutOffender(Offender{IP: ip, Score: 60})
	if err := fs.DeleteOffender(ip); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := fs.GetOffender(ip); ok {
		t.Error("expected offender to be gone after delete")
	}
}

func TestFileStore_Queue_EnqueueDequeueAck(t *testing.T) {
	dir := t.TempDir()
	fs, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	ip := mustAddr(t, "203.0.113.44")
	if err := fs.Enqueue(Observation{IP: ip, Kind: "ssh_failed_login"}); err != nil {
		t.Fatal(err)
	}
	if err := fs.Enqueue(Observation{IP: ip, Kind: "ssh_failed_login"}); err != nil {
		t.Fatal(err)
	}

	depth, err := fs.QueueDepth()
	if err != nil || depth != 2 {
		t.Fatalf("QueueDepth = %d, %v, want 2, nil", depth, err)
	}

	batch, err := fs.Dequeue(1)
	if err != nil || len(batch) != 1 {
		t.Fatalf("Dequeue(1) = %v, %v, want 1 entry", batch, err)
	}
	if batch[0].ID == "" {
		t.Error("expected Enqueue to assign a non-empty ID")
	}

	if err := fs.Ack([]string{batch[0].ID}); err != nil {
		t.Fatal(err)
	}
	depth, _ = fs.QueueDepth()
	if depth != 1 {
		t.Errorf("QueueDepth after ack = %d, want 1", depth)
	}
}

func TestFileStore_Queue_BoundedNeverGrowsUnbounded(t *testing.T) {
	dir := t.TempDir()
	fs, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	fs.maxQueueEntries = 5

	ip := mustAddr(t, "203.0.113.44")
	for i := 0; i < 20; i++ {
		if err := fs.Enqueue(Observation{IP: ip, Kind: "ssh_failed_login"}); err != nil {
			t.Fatal(err)
		}
	}
	depth, err := fs.QueueDepth()
	if err != nil {
		t.Fatal(err)
	}
	if depth != 5 {
		t.Errorf("QueueDepth = %d, want 5 (bounded, oldest dropped)", depth)
	}
}

func TestFileStore_Queue_SurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	fs, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ip := mustAddr(t, "203.0.113.44")
	_ = fs.Enqueue(Observation{IP: ip, Kind: "ssh_failed_login"})
	fs.Close()

	fs2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fs2.Close()
	depth, _ := fs2.QueueDepth()
	if depth != 1 {
		t.Errorf("QueueDepth after reopen = %d, want 1", depth)
	}
}

func TestFileStore_LockContention_SecondOpenFailsFast(t *testing.T) {
	dir := t.TempDir()
	fs, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	if _, err := Open(dir); err == nil {
		t.Fatal("expected a second Open against the same data dir to fail while the first is live")
	}
}

func TestFileStore_LockContention_StaleLockIsRecovered(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "agent.lock")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A PID that (almost certainly) doesn't correspond to a live
	// process, simulating a lock left behind by a crashed agent.
	if err := os.WriteFile(lockPath, []byte("999999\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fs, err := Open(dir)
	if err != nil {
		t.Fatalf("expected a stale lock (dead pid) to be recovered, got: %v", err)
	}
	defer fs.Close()
}

func TestFileStore_Close_ReleasesLockForNextOpen(t *testing.T) {
	dir := t.TempDir()
	fs, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
	fs2, err := Open(dir)
	if err != nil {
		t.Fatalf("expected Open to succeed after Close released the lock, got: %v", err)
	}
	fs2.Close()
}

func TestFileStore_CorruptOffendersFile_ErrorsRatherThanPanics(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "offenders.json"), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("expected Open to error on a corrupt offenders.json, not silently ignore it")
	}
}
