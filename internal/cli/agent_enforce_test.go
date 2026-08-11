package cli

import (
	"strings"
	"testing"

	"github.com/Dyneteq/Breach-Harbor/internal/agent"
)

func TestMain_Agent_Enforce_RequiresExactlyOneFlag(t *testing.T) {
	dir := t.TempDir()
	_, stderr, code := run("agent", "enforce", "--data-dir", dir)
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "exactly one of --on or --off") {
		t.Errorf("expected a clear usage error, got %q", stderr)
	}

	_, _, code = run("agent", "enforce", "--data-dir", dir, "--on", "--off")
	if code != 2 {
		t.Errorf("code = %d, want 2 when both --on and --off are given", code)
	}
}

func TestMain_Agent_Enforce_OnThenOff(t *testing.T) {
	dir := t.TempDir()

	stdout, _, code := run("agent", "enforce", "--data-dir", dir, "--on")
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "now ON") {
		t.Errorf("expected an ON confirmation, got %q", stdout)
	}
	state, err := agent.LoadState(dir)
	if err != nil || !state.Enforcing {
		t.Fatalf("expected state.Enforcing=true, got %+v, err=%v", state, err)
	}
	if state.EnforcingSince == nil {
		t.Error("expected EnforcingSince to be set")
	}

	stdout, _, code = run("agent", "enforce", "--data-dir", dir, "--off")
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "now OFF") {
		t.Errorf("expected an OFF confirmation, got %q", stdout)
	}
	state, err = agent.LoadState(dir)
	if err != nil || state.Enforcing {
		t.Fatalf("expected state.Enforcing=false, got %+v, err=%v", state, err)
	}
	if state.EnforcingSince != nil {
		t.Error("expected EnforcingSince to be cleared")
	}
}

func TestMain_Agent_Enforce_JSON(t *testing.T) {
	dir := t.TempDir()
	stdout, _, code := run("agent", "enforce", "--data-dir", dir, "--on", "--json")
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout, `"enforcing": true`) {
		t.Errorf("expected JSON reporting enforcing=true, got %q", stdout)
	}
}
