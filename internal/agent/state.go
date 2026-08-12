package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DefaultDryRunDuration is how long a fresh install stays in dry run
// before the user must explicitly run `agent enforce --on` — 24h, per
// PLAN.md's example `agent run` output ("Observing for 24h so you can
// review what would happen").
const DefaultDryRunDuration = 24 * time.Hour

// State is the agent's small persisted run state — not offender data
// (that's internal/store), just "when did this install first run"
// and "is enforcement currently on." It survives restarts so a
// restarted agent doesn't reset its dry-run countdown or forget it
// was already enforcing.
type State struct {
	StartedAt      time.Time  `json:"started_at"`
	DryRunUntil    time.Time  `json:"dry_run_until"`
	Enforcing      bool       `json:"enforcing"`
	EnforcingSince *time.Time `json:"enforcing_since,omitempty"`
	PID            int        `json:"pid"`
}

func statePath(dataDir string) string { return filepath.Join(dataDir, "agent-state.json") }

// LoadState reads the persisted state, or returns a fresh one (dry
// run starting now) if this is the first run for this data directory.
func LoadState(dataDir string) (State, error) {
	data, err := os.ReadFile(statePath(dataDir))
	if err != nil {
		if os.IsNotExist(err) {
			now := time.Now()
			return State{StartedAt: now, DryRunUntil: now.Add(DefaultDryRunDuration)}, nil
		}
		return State{}, fmt.Errorf("read agent state: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, fmt.Errorf("corrupt agent state file %s: %w", statePath(dataDir), err)
	}
	return s, nil
}

// SaveState writes state atomically (write-to-temp, then rename). The
// temp file gets a unique name per call (via os.CreateTemp) rather
// than a fixed "agent-state.json.tmp" — internal/server's local-agent
// manager can call this concurrently with the same agent process's
// own startup write (Agent.Run sets State.PID before entering its
// loop), and a shared tmp name let one writer's rename race another's,
// occasionally leaving the loser to rename a file that no longer
// existed.
func SaveState(dataDir string, s State) error {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("create data directory %s: %w", dataDir, err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dataDir, "agent-state.*.tmp")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, statePath(dataDir)); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}
