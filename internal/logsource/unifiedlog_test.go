package logsource

import (
	"bufio"
	"context"
	"errors"
	"os"
	"runtime"
	"testing"
)

func TestParseUnifiedLogLine(t *testing.T) {
	f, err := os.Open("testdata/unifiedlog_ssh.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var events []Event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if ev, ok := parseUnifiedLogLine(scanner.Text()); ok {
			events = append(events, ev)
		}
	}

	// The "Filtering the log data using..." header line and the
	// "Accepted password" line must both be ignored; only the 2
	// "Failed password" lines match.
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(events), events)
	}
	if events[0].IP.String() != "203.0.113.44" {
		t.Errorf("events[0].IP = %s, want 203.0.113.44", events[0].IP)
	}
	if events[0].Kind != EventSSHFailedLogin {
		t.Errorf("events[0].Kind = %s, want %s", events[0].Kind, EventSSHFailedLogin)
	}
	if events[0].Time.IsZero() {
		t.Error("expected a parsed timestamp from the ndjson timestamp field, got zero value")
	}
	if events[0].Fields["process"] != "sshd" {
		t.Errorf("events[0].process = %q, want sshd", events[0].Fields["process"])
	}
	if events[1].IP.String() != "198.51.100.9" {
		t.Errorf("events[1].IP = %s, want 198.51.100.9", events[1].IP)
	}
}

func TestParseUnifiedLogLine_MalformedNeverPanics(t *testing.T) {
	lines := []string{
		"",
		"not json",
		`Filtering the log data using "process == \"sshd\""`,
		`{"eventMessage": "unrelated log line"}`,
	}
	for _, l := range lines {
		if _, ok := parseUnifiedLogLine(l); ok {
			t.Errorf("expected non-matching line %q to be rejected", l)
		}
	}
}

func TestUnifiedLog_Probe_NotDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("this case only exercises the non-darwin branch")
	}
	s := NewUnifiedLog()
	res := s.Probe(context.Background())
	if res.Available {
		t.Error("expected Available=false on a non-macOS host")
	}
}

func TestUnifiedLog_Probe_NoLogBinary(t *testing.T) {
	s := &UnifiedLog{run: &fakeJournalRunner{lookPath: func(name string) (string, error) {
		return "", errors.New("not found")
	}}}
	res := s.Probe(context.Background())
	if res.Available {
		t.Error("expected Available=false when log(1) is missing")
	}
}

func TestUnifiedLog_Probe_AvailableOnDarwinWithLogBinary(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("this case only exercises the darwin branch")
	}
	s := &UnifiedLog{run: &fakeJournalRunner{}} // default LookPath succeeds
	res := s.Probe(context.Background())
	if !res.Available {
		t.Fatalf("expected Available=true on macOS with log(1) present, got Detail=%q", res.Detail)
	}
}
