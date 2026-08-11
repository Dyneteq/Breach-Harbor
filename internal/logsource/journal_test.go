package logsource

import (
	"bufio"
	"context"
	"errors"
	"os"
	"testing"
)

func TestParseJournalLine(t *testing.T) {
	f, err := os.Open("testdata/journal_ssh.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var events []Event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if ev, ok := parseJournalLine(scanner.Text()); ok {
			events = append(events, ev)
		}
	}

	// 2 failed-login MESSAGE lines; the "Accepted password" and
	// "pam_unix" lines must be ignored.
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
		t.Error("expected a parsed timestamp from __REALTIME_TIMESTAMP, got zero value")
	}
	if events[0].Fields["unit"] != "ssh.service" {
		t.Errorf("events[0].unit = %q, want ssh.service", events[0].Fields["unit"])
	}
}

func TestParseJournalLine_MalformedNeverPanics(t *testing.T) {
	lines := []string{"", "not json", `{"MESSAGE": "unrelated log line"}`}
	for _, l := range lines {
		if _, ok := parseJournalLine(l); ok {
			t.Errorf("expected non-matching line %q to be rejected", l)
		}
	}
}

// fakeJournalRunner scripts LookPath/Run for Journal.Probe without
// touching a real journalctl/systemctl binary.
type fakeJournalRunner struct {
	lookPath func(name string) (string, error)
	run      func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (f *fakeJournalRunner) LookPath(name string) (string, error) {
	if f.lookPath != nil {
		return f.lookPath(name)
	}
	return "/usr/bin/" + name, nil
}

func (f *fakeJournalRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if f.run != nil {
		return f.run(ctx, name, args...)
	}
	return nil, nil
}

func TestJournal_Probe_NoJournalctl(t *testing.T) {
	j := &Journal{run: &fakeJournalRunner{lookPath: func(name string) (string, error) {
		return "", errors.New("not found")
	}}}
	res := j.Probe(context.Background())
	if res.Available {
		t.Error("expected Available=false when journalctl is missing")
	}
}

func TestJournal_Probe_NoSSHUnit(t *testing.T) {
	j := &Journal{run: &fakeJournalRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("unit not found")
	}}}
	res := j.Probe(context.Background())
	if res.Available {
		t.Error("expected Available=false when no candidate unit exists")
	}
}

func TestJournal_Probe_FindsSshdService(t *testing.T) {
	j := &Journal{run: &fakeJournalRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		// Fail for ssh.service, succeed for sshd.service.
		for _, a := range args {
			if a == "ssh.service" {
				return nil, errors.New("not found")
			}
		}
		return nil, nil
	}}}
	res := j.Probe(context.Background())
	if !res.Available {
		t.Fatalf("expected Available=true, got Detail=%q", res.Detail)
	}
	if res.Detail != "unit=sshd.service" {
		t.Errorf("Detail = %q, want unit=sshd.service", res.Detail)
	}
}
