package logsource

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"time"
)

// unifiedLogSSHPredicate scopes `log stream`/`log show` to sshd only —
// the macOS equivalent of journal.go's `-u ssh.service` filter.
const unifiedLogSSHPredicate = `process == "sshd"`

// UnifiedLog watches macOS's unified logging system (log(1)) for
// sshd failed-login lines via `log stream --style ndjson --predicate
// 'process == "sshd"'`. This is the macOS analog of journal.go: OpenSSH
// on macOS logs through the same syslog-style "Failed password for..."
// message text as Linux, just carried by a different transport, so it
// reuses journal.go's journalFailedPasswordRe rather than redefining
// its own.
type UnifiedLog struct {
	run runner
}

// NewUnifiedLog returns a UnifiedLog source.
func NewUnifiedLog() *UnifiedLog {
	return &UnifiedLog{run: execRunner{}}
}

func (s *UnifiedLog) Name() string { return "macOS unified log" }

func (s *UnifiedLog) Probe(ctx context.Context) ProbeResult {
	if runtime.GOOS != "darwin" {
		return ProbeResult{Source: s.Name(), Available: false, Detail: "not a macOS host"}
	}
	if _, err := s.run.LookPath("log"); err != nil {
		return ProbeResult{Source: s.Name(), Available: false, Detail: "log(1) not found — unexpected on macOS"}
	}
	return ProbeResult{Source: s.Name(), Available: true, Detail: `predicate: process == "sshd"`}
}

func (s *UnifiedLog) Watch(ctx context.Context, out chan<- Event) error {
	cmd := exec.CommandContext(ctx, "log", "stream", "--style", "ndjson", "--predicate", unifiedLogSSHPredicate)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("log stream: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("log stream: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		// `log stream` prints one human-readable "Filtering the log
		// data using ..." line before the ndjson stream starts;
		// parseUnifiedLogLine silently rejects it like any other
		// non-matching line, same as journal.go/authlog.go do for
		// their own non-matching lines.
		ev, ok := parseUnifiedLogLine(scanner.Text())
		if !ok {
			continue
		}
		select {
		case out <- ev:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return cmd.Wait()
}

// unifiedLogEntry is the subset of `log stream --style ndjson`'s
// per-line JSON object this package cares about.
type unifiedLogEntry struct {
	Timestamp    string `json:"timestamp"`
	Process      string `json:"process"`
	EventMessage string `json:"eventMessage"`
}

func parseUnifiedLogLine(line string) (Event, bool) {
	var e unifiedLogEntry
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		return Event{}, false
	}
	m := journalFailedPasswordRe.FindStringSubmatch(e.EventMessage)
	if m == nil {
		return Event{}, false
	}
	ip, err := netip.ParseAddr(m[1])
	if err != nil {
		return Event{}, false
	}
	return Event{
		Source: "macos unified log",
		Kind:   EventSSHFailedLogin,
		IP:     ip,
		Time:   parseUnifiedLogTimestamp(e.Timestamp),
		Raw:    e.EventMessage,
		Fields: map[string]string{"process": e.Process},
	}, true
}

// parseUnifiedLogTimestamp parses `log stream --style ndjson`'s
// "timestamp" field, e.g. "2024-01-15 10:23:45.123456-0800".
func parseUnifiedLogTimestamp(raw string) time.Time {
	ts, err := time.Parse("2006-01-02 15:04:05.999999-0700", raw)
	if err != nil {
		return time.Now()
	}
	return ts
}
