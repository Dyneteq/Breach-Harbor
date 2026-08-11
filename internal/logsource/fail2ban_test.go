package logsource

import (
	"bufio"
	"context"
	"os"
	"testing"
)

func TestParseFail2banLine(t *testing.T) {
	f, err := os.Open("testdata/fail2ban.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var events []Event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if ev, ok := parseFail2banLine(scanner.Text()); ok {
			events = append(events, ev)
		}
	}

	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (Ban lines only, Unban ignored): %+v", len(events), events)
	}
	if events[0].IP.String() != "203.0.113.44" {
		t.Errorf("events[0].IP = %s, want 203.0.113.44", events[0].IP)
	}
	if events[0].Kind != EventFail2banBan {
		t.Errorf("events[0].Kind = %s, want %s", events[0].Kind, EventFail2banBan)
	}
	if events[0].Fields["jail"] != "sshd" {
		t.Errorf("events[0].jail = %q, want sshd", events[0].Fields["jail"])
	}
	if events[1].IP.String() != "198.51.100.9" {
		t.Errorf("events[1].IP = %s, want 198.51.100.9", events[1].IP)
	}
	if events[1].Fields["jail"] != "nginx-botsearch" {
		t.Errorf("events[1].jail = %q, want nginx-botsearch", events[1].Fields["jail"])
	}
}

func TestParseFail2banLine_IgnoresNoise(t *testing.T) {
	if _, ok := parseFail2banLine("not a fail2ban line at all"); ok {
		t.Error("expected garbage line to be ignored, not parsed")
	}
	if _, ok := parseFail2banLine(""); ok {
		t.Error("expected empty line to be ignored")
	}
}

func TestFail2ban_Probe_NotFound(t *testing.T) {
	s := NewFail2ban("/nonexistent/path/fail2ban.log")
	res := s.Probe(context.Background())
	if res.Available {
		t.Error("expected Available=false for a missing file")
	}
	if res.Err != nil {
		t.Errorf("a missing file should report via Detail, not Err, got %v", res.Err)
	}
}

func TestFail2ban_Probe_Found(t *testing.T) {
	s := NewFail2ban("testdata/fail2ban.log")
	res := s.Probe(nil) //nolint:staticcheck
	if !res.Available {
		t.Errorf("expected Available=true for an existing file, got Detail=%q", res.Detail)
	}
}
