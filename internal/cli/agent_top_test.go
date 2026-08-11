package cli

import (
	"strings"
	"testing"
)

func TestMain_Agent_Top_EmptyDataDir(t *testing.T) {
	dir := t.TempDir()
	stdout, _, code := run("agent", "top", "--data-dir", dir)
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "attackers tracked") {
		t.Errorf("expected a summary line, got %q", stdout)
	}
}

func TestMain_Agent_Top_JSON(t *testing.T) {
	dir := t.TempDir()
	stdout, _, code := run("agent", "top", "--data-dir", dir, "--json")
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	trimmed := strings.TrimSpace(stdout)
	if trimmed != "null" && !strings.HasPrefix(trimmed, "[") {
		t.Errorf("expected a JSON array (or null) for an empty offender list, got %q", stdout)
	}
}
