package cli

import (
	"bytes"
	"strings"
	"testing"
)

// runAgentTrace's happy path needs a real systemd/journalctl host to
// exercise end to end, which this test environment isn't. What's
// tested here is everything that doesn't: the journalctl-missing
// error path (true on this dev machine and most CI runners), and the
// pure line-formatting/terminal-detection helpers it's built on.

func TestMain_Agent_Trace_NoJournalctl(t *testing.T) {
	if _, err := lookPathJournalctl(); err == nil {
		t.Skip("journalctl is present on this host; the not-found path can't be exercised here")
	}
	stdout, stderr, code := run("agent", "trace")
	if code != 1 {
		t.Errorf("code = %d, want 1; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "journalctl") {
		t.Errorf("expected an actionable journalctl-not-found message, got stderr=%q", stderr)
	}
}

func TestWriteTraceLine_NoColor(t *testing.T) {
	var buf bytes.Buffer
	writeTraceLine(&buf, "14:04:39 would   block 45.148.10.72 (limit 10/60s)", false)
	got := buf.String()
	if strings.ContainsAny(got, "\x1b") {
		t.Errorf("expected no ANSI codes, got %q", got)
	}
	if got != "14:04:39 would   block 45.148.10.72 (limit 10/60s)\n" {
		t.Errorf("unexpected passthrough output: %q", got)
	}
}

func TestWriteTraceLine_Color(t *testing.T) {
	cases := []struct {
		tag       string
		wantColor string
	}{
		{"ready", ansiAccent},
		{"mode", ansiAccent},
		{"summary", ansiAccent},
		{"would", ansiDanger},
		{"block", ansiDanger},
		{"warn", ansiWarn},
		{"seen", ""},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		writeTraceLine(&buf, "14:04:39 "+c.tag+"   some message", true)
		got := buf.String()
		if !strings.Contains(got, ansiDim+"14:04:39"+ansiReset) {
			t.Errorf("tag %q: expected dimmed timestamp, got %q", c.tag, got)
		}
		if !strings.Contains(got, "some message") {
			t.Errorf("tag %q: expected message preserved, got %q", c.tag, got)
		}
		if c.wantColor != "" && !strings.Contains(got, c.wantColor+c.tag) {
			t.Errorf("tag %q: expected color %q applied to tag, got %q", c.tag, c.wantColor, got)
		}
	}
}

func TestWriteTraceLine_MalformedPassthrough(t *testing.T) {
	// A single token has no time/tag/message split at all, so it can't
	// match the "HH:MM:SS tag message" shape regardless of spacing.
	var buf bytes.Buffer
	writeTraceLine(&buf, "startup", true)
	got := buf.String()
	if got != "startup\n" {
		t.Errorf("expected malformed lines to pass through unmodified, got %q", got)
	}
}

func TestIsTerminal_NonFile(t *testing.T) {
	var buf bytes.Buffer
	if isTerminal(&buf) {
		t.Error("expected a bytes.Buffer to never report as a terminal")
	}
}
