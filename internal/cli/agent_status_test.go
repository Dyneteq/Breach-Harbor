package cli

import (
	"strings"
	"testing"
)

func TestMain_Agent_Status_NotRunning(t *testing.T) {
	dir := t.TempDir()
	stdout, _, code := run("agent", "status", "--data-dir", dir)
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "not running") {
		t.Errorf("expected a not-running message for a fresh data dir, got %q", stdout)
	}
}

func TestMain_Agent_Status_JSON(t *testing.T) {
	dir := t.TempDir()
	stdout, _, code := run("agent", "status", "--data-dir", dir, "--json")
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout, `"running"`) {
		t.Errorf("expected JSON with a running field, got %q", stdout)
	}
}
