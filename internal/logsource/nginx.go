package logsource

import (
	"context"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	defaultNginxAccessLog = "/var/log/nginx/access.log"
	defaultNginxErrorLog  = "/var/log/nginx/error.log"
)

// sensitivePaths are commonly-scanned paths with no legitimate reason
// to be hit on most sites — a single request to one is a meaningful
// signal, unlike an ordinary 404. This is intentionally a short,
// curated list rather than an exhaustive scanner-signature database.
var sensitivePaths = []string{
	"/wp-login.php",
	"/wp-admin",
	"/.env",
	"/xmlrpc.php",
	"/.git/config",
	"/phpmyadmin",
	"/.aws/credentials",
}

// nginxCombinedRe matches the standard combined log format:
//
//	203.0.113.44 - - [15/Jan/2024:10:23:45 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "curl/8.0"
var nginxCombinedRe = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)(?:\s+\S+)?" (\d{3}) \d+`)

// Nginx tails an access log and flags single requests to sensitive
// paths — a scan for /wp-login.php or /.env is worth flagging on its
// own, unlike counting every request, so this deliberately doesn't
// implement its own burst window; internal/agent/offender.go's
// sliding-window scorer decides when enough of these add up to
// block-eligible.
type Nginx struct {
	AccessPath string
	ErrorPath  string
}

// NewNginx returns an Nginx source. Pass "" for either path to use
// the standard /var/log/nginx/{access,error}.log locations.
func NewNginx(accessPath, errorPath string) *Nginx {
	if accessPath == "" {
		accessPath = defaultNginxAccessLog
	}
	if errorPath == "" {
		errorPath = defaultNginxErrorLog
	}
	return &Nginx{AccessPath: accessPath, ErrorPath: errorPath}
}

func (s *Nginx) Name() string { return "nginx" }

func (s *Nginx) Probe(ctx context.Context) ProbeResult {
	if !fileReadable(s.AccessPath) {
		return ProbeResult{Source: s.Name(), Available: false, Detail: s.AccessPath + ": not found"}
	}
	return ProbeResult{Source: s.Name(), Available: true, Detail: s.AccessPath + ", " + s.ErrorPath}
}

func (s *Nginx) Watch(ctx context.Context, out chan<- Event) error {
	t := &Tailer{Path: s.AccessPath}
	return t.Watch(ctx, func(line string) {
		ev, ok := parseNginxAccessLine(line)
		if !ok {
			return
		}
		select {
		case out <- ev:
		case <-ctx.Done():
		}
	})
}

func isSensitivePath(path string) (string, bool) {
	lower := strings.ToLower(path)
	for _, p := range sensitivePaths {
		if strings.HasPrefix(lower, p) {
			return p, true
		}
	}
	return "", false
}

func parseNginxAccessLine(line string) (Event, bool) {
	m := nginxCombinedRe.FindStringSubmatch(line)
	if m == nil {
		return Event{}, false
	}
	ip, err := netip.ParseAddr(m[1])
	if err != nil {
		return Event{}, false
	}
	path := m[4]
	matched, ok := isSensitivePath(path)
	if !ok {
		return Event{}, false
	}
	ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
	if err != nil {
		ts = time.Now()
	}
	return Event{
		Source: "nginx",
		Kind:   EventHTTPSuspicious,
		IP:     ip,
		Time:   ts,
		Raw:    line,
		Fields: map[string]string{"method": m[3], "path": path, "status": m[5], "matched": matched},
	}, true
}

func fileReadable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	f.Close()
	return true
}
