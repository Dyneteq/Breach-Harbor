package logsource

import (
	"bufio"
	"os"
	"testing"
)

func countEventsInFixture(t *testing.T, path string, parse func(string) (Event, bool)) []Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var events []Event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if ev, ok := parse(scanner.Text()); ok {
			events = append(events, ev)
		}
	}
	return events
}

func TestParseAuthLogLine_Ubuntu2204(t *testing.T) {
	events := countEventsInFixture(t, "testdata/auth_ubuntu2204.log", parseAuthLogLine)
	// 3 failed-login lines: root, invalid user admin, invalid user test
	// (IPv6). Accepted-password and CRON lines must be ignored.
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3: %+v", len(events), events)
	}
	if events[0].IP.String() != "203.0.113.44" {
		t.Errorf("events[0].IP = %s, want 203.0.113.44", events[0].IP)
	}
	if events[2].IP.String() != "2001:db8::1" {
		t.Errorf("events[2].IP = %s, want 2001:db8::1 (ipv6 source)", events[2].IP)
	}
	for _, ev := range events {
		if ev.Kind != EventSSHFailedLogin {
			t.Errorf("event kind = %s, want %s", ev.Kind, EventSSHFailedLogin)
		}
	}
}

func TestParseAuthLogLine_Ubuntu2404(t *testing.T) {
	events := countEventsInFixture(t, "testdata/auth_ubuntu2404.log", parseAuthLogLine)
	// 2 "Failed password" lines for 192.0.2.187 + 1 for 198.51.100.9;
	// the "Connection closed" preauth line must be ignored.
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3: %+v", len(events), events)
	}
}

func TestParseAuthLogLine_Debian12(t *testing.T) {
	events := countEventsInFixture(t, "testdata/auth_debian12.log", parseAuthLogLine)
	// "Invalid user" alone (no "Failed password") must not match on its
	// own. Debian's syslog collapses repeats into a "message repeated N
	// times: [...]" line that still contains the original "Failed
	// password..." text, so it matches too (undercounting the true
	// repeat count by not parsing N — acceptable for M1's threshold
	// scoring, which only needs "more than one" to add up over time).
	// So: root x2 (one direct, one via the repeated-message line) +
	// oracle x1 = 3.
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3: %+v", len(events), events)
	}
	if events[2].IP.String() != "198.51.100.220" {
		t.Errorf("events[2].IP = %s, want 198.51.100.220", events[2].IP)
	}
}

func TestParseAuthLogLine_MalformedNeverPanics(t *testing.T) {
	lines := []string{
		"",
		"garbage",
		"Aug 11 sshd[1]: Failed password for from port ssh2",
		"Failed password for root from 999.999.999.999 port 22 ssh2",
	}
	for _, l := range lines {
		if _, ok := parseAuthLogLine(l); ok {
			t.Errorf("expected malformed line %q to be rejected, not parsed", l)
		}
	}
}
