package logsource

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"time"
)

// Tailer watches a single file for newly appended lines, reopening it
// across rotation (a new inode replacing the old one) and truncation
// (the same inode shrinking in place, e.g. logrotate's copytruncate).
// It never blocks if the file doesn't exist yet — it just keeps
// polling — which is how authlog.go/nginx.go/fail2ban.go satisfy
// "never fail because one source is missing."
type Tailer struct {
	Path string
	// PollInterval defaults to 1s if zero. Tests use a much shorter
	// interval so they don't take a full second per assertion.
	PollInterval time.Duration

	f       *os.File
	info    os.FileInfo
	pending []byte
	opened  bool
}

// Watch polls Path and calls onLine for each newly appended, complete
// line (trailing \r\n/\n stripped) until ctx is cancelled.
func (t *Tailer) Watch(ctx context.Context, onLine func(line string)) error {
	interval := t.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	defer func() {
		if t.f != nil {
			t.f.Close()
		}
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			t.tick(onLine)
		}
	}
}

// tick runs a single poll pass. Exported to the package (not the
// public API) so tests can drive it deterministically instead of
// waiting on real ticker ticks.
func (t *Tailer) tick(onLine func(line string)) {
	stat, err := os.Stat(t.Path)
	if err != nil {
		// Not present (yet, or anymore): stay quiet, keep polling.
		if t.f != nil {
			t.f.Close()
			t.f = nil
		}
		return
	}

	if t.f == nil {
		f, err := os.Open(t.Path)
		if err != nil {
			return
		}
		if !t.opened {
			// First-ever open: tail semantics, no history replay.
			_, _ = f.Seek(0, io.SeekEnd)
			t.opened = true
		}
		t.f = f
		t.info = stat
		t.readAvailable(onLine)
		return
	}

	if !os.SameFile(t.info, stat) {
		// Rotated: old inode replaced by a new dirent. Drain whatever
		// the old fd still has, then switch to the new file from its
		// start (it's new content, not history).
		t.readAvailable(onLine)
		t.f.Close()
		f, err := os.Open(t.Path)
		if err != nil {
			t.f = nil
			return
		}
		t.f = f
		t.info = stat
		t.pending = nil
		t.readAvailable(onLine)
		return
	}

	if stat.Size() < t.info.Size() {
		// Truncated in place (copytruncate): same inode, shorter file.
		// Reset to the start so newly appended content is seen.
		_, _ = t.f.Seek(0, io.SeekStart)
		t.pending = nil
	}
	t.info = stat
	t.readAvailable(onLine)
}

func (t *Tailer) readAvailable(onLine func(line string)) {
	buf := make([]byte, 64*1024)
	for {
		n, err := t.f.Read(buf)
		if n > 0 {
			t.pending = append(t.pending, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	for {
		i := bytes.IndexByte(t.pending, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(t.pending[:i]), "\r")
		t.pending = t.pending[i+1:]
		if line != "" {
			onLine(line)
		}
	}
}
