package logsource

import (
	"context"
	"testing"
)

func TestProbeAll_NeverPanics(t *testing.T) {
	// On a Linux CI sandbox, none of these tools/files are present, so
	// every source comes back Available:false with a human Detail,
	// never a crash and never a bare Err for "just not installed." On
	// a real macOS host, UnifiedLog will legitimately report
	// Available:true instead — this test only asserts the shape of
	// the results (every source names itself; every unavailable one
	// explains why), not that all five are unavailable everywhere.
	results := ProbeAll(context.Background())
	if len(results) != 5 {
		t.Fatalf("got %d probe results, want 5", len(results))
	}
	for _, r := range results {
		if r.Source == "" {
			t.Error("expected every ProbeResult to name its Source")
		}
		if !r.Available && r.Detail == "" {
			t.Errorf("%s: unavailable source must explain why via Detail", r.Source)
		}
	}
}

func TestDetect_OnlyReturnsAvailableSources(t *testing.T) {
	// Same sandbox assumption as above: nothing should detect as
	// available, but Detect must not error or panic either way.
	sources := Detect(context.Background())
	for _, s := range sources {
		if !s.Probe(context.Background()).Available {
			t.Errorf("Detect returned %s but its own Probe reports unavailable", s.Name())
		}
	}
}
