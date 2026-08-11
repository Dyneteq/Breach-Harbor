package logsource

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTailer_MissingFileNeverPanics(t *testing.T) {
	tl := &Tailer{Path: filepath.Join(t.TempDir(), "does-not-exist.log")}
	var lines []string
	tl.tick(func(l string) { lines = append(lines, l) })
	tl.tick(func(l string) { lines = append(lines, l) })
	if len(lines) != 0 {
		t.Errorf("expected no lines from a missing file, got %v", lines)
	}
}

func TestTailer_NoHistoryReplayOnFirstOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(path, []byte("old line 1\nold line 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tl := &Tailer{Path: path}
	var lines []string
	tl.tick(func(l string) { lines = append(lines, l) }) // first open: seeks to EOF
	if len(lines) != 0 {
		t.Fatalf("expected no history replay on first open, got %v", lines)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("new line 1\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	tl.tick(func(l string) { lines = append(lines, l) })
	if len(lines) != 1 || lines[0] != "new line 1" {
		t.Fatalf("got %v, want [\"new line 1\"]", lines)
	}
}

func TestTailer_HandlesRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	tl := &Tailer{Path: path}
	var lines []string
	tl.tick(func(l string) { lines = append(lines, l) }) // first open, empty file

	appendLine := func(s string) {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(s + "\n"); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	appendLine("before rotation")
	tl.tick(func(l string) { lines = append(lines, l) })

	// Simulate logrotate: rename the old file away, create a fresh one.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("after rotation\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tl.tick(func(l string) { lines = append(lines, l) })

	want := []string{"before rotation", "after rotation"}
	if len(lines) != len(want) {
		t.Fatalf("got %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("lines[%d] = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestTailer_HandlesCopyTruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(path, []byte("line one\nline two\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tl := &Tailer{Path: path}
	var lines []string
	tl.tick(func(l string) { lines = append(lines, l) }) // first open, seeks to EOF

	// copytruncate: same inode, file shrinks then grows again.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("line three\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	tl.tick(func(l string) { lines = append(lines, l) })
	if len(lines) != 1 || lines[0] != "line three" {
		t.Fatalf("got %v, want [\"line three\"]", lines)
	}
}

func TestTailer_HoldsBackPartialLineAcrossTicks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	tl := &Tailer{Path: path}
	var lines []string
	tl.tick(func(l string) { lines = append(lines, l) }) // first open

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("partial line without newline yet"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	tl.tick(func(l string) { lines = append(lines, l) })
	if len(lines) != 0 {
		t.Fatalf("expected the partial line to be held back, got %v", lines)
	}

	f, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(" now complete\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	tl.tick(func(l string) { lines = append(lines, l) })
	want := "partial line without newline yet now complete"
	if len(lines) != 1 || lines[0] != want {
		t.Fatalf("got %v, want [%q]", lines, want)
	}
}
