// Package logsource provides pluggable observation sources for the
// standalone agent — systemd journal, /var/log/auth.log, nginx access
// logs, and fail2ban's own ban log. Each Source watches one thing and
// emits Events on a channel; internal/agent turns those into scored
// Offenders. A source that isn't present on this host reports itself
// as unavailable via Probe rather than erroring, so a fresh install
// with only some of these installed still works out of the box.
package logsource

import (
	"context"
	"net/netip"
	"time"
)

// EventKind classifies what an Event represents. Weights for each kind
// live in internal/agent/offender.go, not here — this package only
// observes and reports, it never scores.
type EventKind string

const (
	// EventSSHFailedLogin is a single failed SSH authentication attempt.
	EventSSHFailedLogin EventKind = "ssh_failed_login"
	// EventHTTPSuspicious is a single HTTP request to a sensitive path
	// (e.g. /wp-login.php, /.env) seen in a web server access log.
	EventHTTPSuspicious EventKind = "http_suspicious"
	// EventFail2banBan is a "Ban" line fail2ban itself already wrote —
	// fail2ban did its own correlation, so this is trusted as-is.
	EventFail2banBan EventKind = "fail2ban_ban"
)

// Event is one observation from a Source.
type Event struct {
	Source string
	Kind   EventKind
	IP     netip.Addr
	Time   time.Time
	Raw    string
	Fields map[string]string
}

// ProbeResult is what Probe reports about a Source's availability on
// this host.
type ProbeResult struct {
	Source    string
	Available bool
	Detail    string
	Err       error
}

// Source is one pluggable observation source.
type Source interface {
	// Name is a short identifier, e.g. "fail2ban" or "nginx".
	Name() string

	// Probe reports whether this source's inputs (files, binaries,
	// units) are present, without mutating anything or blocking.
	// "Not present" is reported via Available:false and a human
	// Detail, never via Err — Err is reserved for genuinely
	// unexpected failures (e.g. a permissions error on a file that
	// does exist).
	Probe(ctx context.Context) ProbeResult

	// Watch emits Events on out as they happen. It must reopen files
	// across rotation and must never block startup — if its input
	// isn't present yet, it keeps polling rather than returning an
	// error immediately. Watch returns when ctx is cancelled.
	Watch(ctx context.Context, out chan<- Event) error
}

// All is every Source this build knows how to watch, in build-order
// (highest value / lowest effort first — see PLAN.md). Detect and
// ProbeAll both iterate this list so adding a new source only means
// adding it here.
func All() []Source {
	return []Source{
		NewFail2ban(""),
		NewJournal(""),
		NewAuthLog(""),
		NewNginx("", ""),
	}
}

// ProbeAll probes every known source, regardless of availability —
// used by `breachharbor doctor` and `agent sources` to report the
// full picture (including what's missing and why).
func ProbeAll(ctx context.Context) []ProbeResult {
	sources := All()
	results := make([]ProbeResult, len(sources))
	for i, s := range sources {
		results[i] = s.Probe(ctx)
	}
	return results
}

// Detect returns only the sources that are actually available on this
// host — what `agent run` actually watches.
func Detect(ctx context.Context) []Source {
	var found []Source
	for _, s := range All() {
		if s.Probe(ctx).Available {
			found = append(found, s)
		}
	}
	return found
}
