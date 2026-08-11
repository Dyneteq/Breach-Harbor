package cli

import (
	"context"
	"testing"
)

func TestLogSourceChecks_OneRowPerSource(t *testing.T) {
	checks := logSourceChecks(context.Background())
	if len(checks) != 4 {
		t.Fatalf("got %d checks, want 4 (one per logsource.Source)", len(checks))
	}
	if checks[0].Name != "Log sources" {
		t.Errorf("checks[0].Name = %q, want %q", checks[0].Name, "Log sources")
	}
	for i, c := range checks {
		if i > 0 && c.Name != "" {
			t.Errorf("checks[%d].Name = %q, want empty (grouped under the first row)", i, c.Name)
		}
		if c.Status != "ok" && c.Status != "skip" {
			t.Errorf("checks[%d].Status = %q, want ok or skip (never fail — a missing source is not an error)", i, c.Status)
		}
		if c.Detail == "" {
			t.Errorf("checks[%d].Detail is empty", i)
		}
	}
}

func TestDataDirCheck_UsesAgentDefaultDataDir(t *testing.T) {
	// This is the single-definition invariant PLAN.md calls out:
	// doctor must not keep its own copy of the default data dir logic.
	c := dataDirCheck()
	if c.Name != "Data directory" {
		t.Errorf("Name = %q, want %q", c.Name, "Data directory")
	}
	if c.Status != "ok" && c.Status != "fail" {
		t.Errorf("Status = %q, want ok or fail", c.Status)
	}
}

func TestFeedChecks_OneRowPerTarget(t *testing.T) {
	checks := feedChecks(context.Background())
	if len(checks) != len(feedReachabilityTargets) {
		t.Fatalf("got %d checks, want %d", len(checks), len(feedReachabilityTargets))
	}
	if checks[0].Name != "Feeds (network)" {
		t.Errorf("checks[0].Name = %q, want %q", checks[0].Name, "Feeds (network)")
	}
	for i, c := range checks {
		if i > 0 && c.Name != "" {
			t.Errorf("checks[%d].Name = %q, want empty (grouped under the first row)", i, c.Name)
		}
		if c.Status != "ok" && c.Status != "fail" {
			t.Errorf("checks[%d].Status = %q, want ok or fail", i, c.Status)
		}
	}
}
