package logsource

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"time"
)

const defaultFail2banLog = "/var/log/fail2ban.log"

// fail2banBanRe matches fail2ban's own ban lines, e.g.:
//
//	2024-01-15 10:23:45,678 fail2ban.actions        [12345]: NOTICE  [sshd] Ban 203.0.113.44
//
// fail2ban already did the correlation that decided this IP deserves
// a ban, so a matched line is trusted outright — see EventFail2banBan's
// weight in internal/agent/offender.go.
var fail2banBanRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+\S+\s+\[\d+\]:\s+NOTICE\s+\[(\S+)\]\s+Ban\s+(\S+)`)

// Fail2ban tails fail2ban's own log and re-emits its Ban lines. This
// is the highest-value, lowest-effort source: if fail2ban is already
// installed and configured with jails, this source lets the agent
// point at that existing work instead of re-deriving it.
type Fail2ban struct {
	Path string
}

// NewFail2ban returns a Fail2ban source. Pass "" for the standard
// /var/log/fail2ban.log path.
func NewFail2ban(path string) *Fail2ban {
	if path == "" {
		path = defaultFail2banLog
	}
	return &Fail2ban{Path: path}
}

func (s *Fail2ban) Name() string { return "fail2ban" }

func (s *Fail2ban) Probe(ctx context.Context) ProbeResult {
	f, err := os.Open(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return ProbeResult{Source: s.Name(), Available: false, Detail: fmt.Sprintf("%s not found — fail2ban not installed", s.Path)}
		}
		return ProbeResult{Source: s.Name(), Available: false, Detail: "cannot read " + s.Path, Err: err}
	}
	f.Close()
	return ProbeResult{Source: s.Name(), Available: true, Detail: s.Path}
}

func (s *Fail2ban) Watch(ctx context.Context, out chan<- Event) error {
	t := &Tailer{Path: s.Path}
	return t.Watch(ctx, func(line string) {
		ev, ok := parseFail2banLine(line)
		if !ok {
			return
		}
		select {
		case out <- ev:
		case <-ctx.Done():
		}
	})
}

func parseFail2banLine(line string) (Event, bool) {
	m := fail2banBanRe.FindStringSubmatch(line)
	if m == nil {
		return Event{}, false
	}
	ip, err := netip.ParseAddr(m[3])
	if err != nil {
		return Event{}, false
	}
	ts, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], time.Local)
	if err != nil {
		ts = time.Now()
	}
	return Event{
		Source: "fail2ban",
		Kind:   EventFail2banBan,
		IP:     ip,
		Time:   ts,
		Raw:    line,
		Fields: map[string]string{"jail": m[2]},
	}, true
}
