package logsource

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

// journalCandidateUnits are tried in order; the first one systemd
// actually knows about wins. Distros vary on whether the SSH daemon
// unit is named ssh.service (Debian/Ubuntu) or sshd.service (RHEL,
// Fedora, and most others).
var journalCandidateUnits = []string{"ssh.service", "sshd.service"}

// journalFailedPasswordRe matches sshd's failed-login log line,
// shared with authlog.go since journald and /var/log/auth.log carry
// the same sshd-formatted message text.
var journalFailedPasswordRe = regexp.MustCompile(`Failed password for (?:invalid user )?\S+ from ([0-9a-fA-F:.]+) port \d+`)

// Journal watches the systemd journal for sshd failed-login lines via
// `journalctl -u <unit> -o json -f`.
type Journal struct {
	run  runner
	unit string // confirmed present unit; cached by Probe, overridable for tests
}

// NewJournal returns a Journal source. Pass "" to auto-detect the SSH
// unit name (tried in journalCandidateUnits order); pass a specific
// unit name to override detection.
func NewJournal(unit string) *Journal {
	return &Journal{run: execRunner{}, unit: unit}
}

func (s *Journal) Name() string { return "systemd journal" }

func (s *Journal) candidateUnits() []string {
	if s.unit != "" {
		return []string{s.unit}
	}
	return journalCandidateUnits
}

// detectUnit finds the first candidate unit systemd actually knows
// about via `systemctl cat` (which fails for a unit that doesn't
// exist, unlike journalctl -u which silently matches nothing).
func (s *Journal) detectUnit(ctx context.Context) (string, bool) {
	for _, u := range s.candidateUnits() {
		if _, err := s.run.Run(ctx, "systemctl", "cat", u); err == nil {
			return u, true
		}
	}
	return "", false
}

func (s *Journal) Probe(ctx context.Context) ProbeResult {
	if _, err := s.run.LookPath("journalctl"); err != nil {
		return ProbeResult{Source: s.Name(), Available: false, Detail: "journalctl not found — not a systemd host"}
	}
	if _, err := s.run.LookPath("systemctl"); err != nil {
		return ProbeResult{Source: s.Name(), Available: false, Detail: "systemctl not found — cannot confirm an SSH unit is present"}
	}
	unit, ok := s.detectUnit(ctx)
	if !ok {
		return ProbeResult{Source: s.Name(), Available: false, Detail: "no ssh.service/sshd.service unit found"}
	}
	s.unit = unit
	return ProbeResult{Source: s.Name(), Available: true, Detail: "unit=" + unit}
}

func (s *Journal) Watch(ctx context.Context, out chan<- Event) error {
	unit := s.unit
	if unit == "" {
		if u, ok := s.detectUnit(ctx); ok {
			unit = u
		} else {
			unit = journalCandidateUnits[0]
		}
	}

	cmd := exec.CommandContext(ctx, "journalctl", "-u", unit, "-o", "json", "--no-pager", "-n", "0", "-f")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("journalctl: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("journalctl: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		ev, ok := parseJournalLine(scanner.Text())
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

type journalEntry struct {
	Message   string `json:"MESSAGE"`
	Unit      string `json:"_SYSTEMD_UNIT"`
	Timestamp string `json:"__REALTIME_TIMESTAMP"` // microseconds since epoch, as a string
}

func parseJournalLine(line string) (Event, bool) {
	var je journalEntry
	if err := json.Unmarshal([]byte(line), &je); err != nil {
		return Event{}, false
	}
	m := journalFailedPasswordRe.FindStringSubmatch(je.Message)
	if m == nil {
		return Event{}, false
	}
	ip, err := netip.ParseAddr(m[1])
	if err != nil {
		return Event{}, false
	}
	return Event{
		Source: "journal",
		Kind:   EventSSHFailedLogin,
		IP:     ip,
		Time:   parseJournalTimestamp(je.Timestamp),
		Raw:    je.Message,
		Fields: map[string]string{"unit": je.Unit},
	}, true
}

func parseJournalTimestamp(raw string) time.Time {
	micros, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || micros == 0 {
		return time.Now()
	}
	return time.UnixMicro(micros)
}
