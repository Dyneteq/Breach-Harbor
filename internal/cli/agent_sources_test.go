package cli

import (
	"strings"
	"testing"
)

func TestMain_Agent_Sources_NeverPanics(t *testing.T) {
	stdout, _, code := run("agent", "sources")
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "log sources") {
		t.Errorf("expected a log sources header, got %q", stdout)
	}
}

func TestMain_Agent_Sources_JSON(t *testing.T) {
	stdout, _, code := run("agent", "sources", "--json")
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout, `"source"`) {
		t.Errorf("expected JSON with a source field, got %q", stdout)
	}
}
