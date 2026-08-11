package logsource

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"
)

const defaultAuthLog = "/var/log/auth.log"

// authLogTimestampRe pulls the leading syslog-style timestamp off an
// auth.log line, e.g. "Jan 15 10:23:45 host sshd[1234]: ...".
var authLogTimestampRe = regexp.MustCompile(`^(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s`)

// AuthLog tails /var/log/auth.log for sshd failed-login lines — the
// non-systemd fallback (older/non-Debian-family distros, or hosts
// where sshd logs to a plain file instead of the journal).
type AuthLog struct {
	Path string
}

// NewAuthLog returns an AuthLog source. Pass "" for the standard
// /var/log/auth.log path.
func NewAuthLog(path string) *AuthLog {
	if path == "" {
		path = defaultAuthLog
	}
	return &AuthLog{Path: path}
}

func (s *AuthLog) Name() string { return "/var/log/auth.log" }

func (s *AuthLog) Probe(ctx context.Context) ProbeResult {
	f, err := os.Open(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return ProbeResult{Source: s.Name(), Available: false, Detail: fmt.Sprintf("%s: not found (systemd-only distro — journal already covers this)", s.Path)}
		}
		return ProbeResult{Source: s.Name(), Available: false, Detail: "cannot read " + s.Path, Err: err}
	}
	f.Close()
	return ProbeResult{Source: s.Name(), Available: true, Detail: s.Path}
}

func (s *AuthLog) Watch(ctx context.Context, out chan<- Event) error {
	t := &Tailer{Path: s.Path}
	return t.Watch(ctx, func(line string) {
		ev, ok := parseAuthLogLine(line)
		if !ok {
			return
		}
		select {
		case out <- ev:
		case <-ctx.Done():
		}
	})
}

func parseAuthLogLine(line string) (Event, bool) {
	if !strings.Contains(line, "sshd") {
		return Event{}, false
	}
	m := journalFailedPasswordRe.FindStringSubmatch(line)
	if m == nil {
		return Event{}, false
	}
	ip, err := netip.ParseAddr(m[1])
	if err != nil {
		return Event{}, false
	}
	return Event{
		Source: "auth.log",
		Kind:   EventSSHFailedLogin,
		IP:     ip,
		Time:   parseAuthLogTimestamp(line),
		Raw:    line,
	}, true
}

// parseAuthLogTimestamp assumes the current year, since syslog-style
// auth.log lines carry no year field. This can be off by one around a
// Dec 31 -> Jan 1 boundary; acceptable for M1 because the scorer only
// cares about recency within a short sliding window (see
// internal/agent/offender.go), not the exact calendar date.
func parseAuthLogTimestamp(line string) time.Time {
	m := authLogTimestampRe.FindStringSubmatch(line)
	if m == nil {
		return time.Now()
	}
	year := time.Now().Year()
	ts, err := time.ParseInLocation("Jan _2 15:04:05 2006", fmt.Sprintf("%s %d", m[1], year), time.Local)
	if err != nil {
		return time.Now()
	}
	return ts
}
