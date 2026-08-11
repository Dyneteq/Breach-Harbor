package store

import "testing"

func TestReadOffenders_WhileStoreIsOpenElsewhere(t *testing.T) {
	dir := t.TempDir()
	fs, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	if err := fs.PutOffender(Offender{IP: mustAddr(t, "203.0.113.44"), Score: 60}); err != nil {
		t.Fatal(err)
	}

	// This must succeed even though fs still holds the exclusive lock
	// — that's the whole point of ReadOffenders not taking one.
	list, err := ReadOffenders(dir)
	if err != nil {
		t.Fatalf("ReadOffenders while the store is open elsewhere: %v", err)
	}
	if len(list) != 1 || list[0].Score != 60 {
		t.Errorf("got %+v, want one offender with score 60", list)
	}
}

func TestReadOffenders_NoFileYet(t *testing.T) {
	list, err := ReadOffenders(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if list != nil {
		t.Errorf("expected nil for a data dir with no offenders.json yet, got %v", list)
	}
}

func TestReadQueueDepth_WhileStoreIsOpenElsewhere(t *testing.T) {
	dir := t.TempDir()
	fs, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	if err := fs.Enqueue(Observation{IP: mustAddr(t, "203.0.113.44"), Kind: "ssh_failed_login"}); err != nil {
		t.Fatal(err)
	}

	depth, err := ReadQueueDepth(dir)
	if err != nil {
		t.Fatalf("ReadQueueDepth while the store is open elsewhere: %v", err)
	}
	if depth != 1 {
		t.Errorf("ReadQueueDepth = %d, want 1", depth)
	}
}

func TestReadQueueDepth_NoFileYet(t *testing.T) {
	depth, err := ReadQueueDepth(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if depth != 0 {
		t.Errorf("ReadQueueDepth = %d, want 0", depth)
	}
}
