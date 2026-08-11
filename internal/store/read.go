package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ReadOffenders and ReadQueueDepth read a data directory's state
// without acquiring the exclusive agent.lock that Open takes. They
// exist so read-only commands (`agent status`, `agent top`, `agent
// sources`) can inspect a *running* agent's state — PLAN.md requires
// those to work unprivileged and, implicitly, concurrently with a live
// `agent run`. Momentary inconsistency from reading mid-write is not a
// concern: every write in filestore.go goes through write-to-temp-
// then-rename, so a reader only ever sees a complete generation of the
// file, never a torn one.
func ReadOffenders(dataDir string) ([]Offender, error) {
	data, err := os.ReadFile(filepath.Join(dataDir, "offenders.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read offenders: %w", err)
	}
	var of offendersFile
	if err := json.Unmarshal(data, &of); err != nil {
		return nil, fmt.Errorf("corrupt offenders file: %w", err)
	}
	sort.Slice(of.Offenders, func(i, j int) bool {
		if of.Offenders[i].Score != of.Offenders[j].Score {
			return of.Offenders[i].Score > of.Offenders[j].Score
		}
		return of.Offenders[i].IP.String() < of.Offenders[j].IP.String()
	})
	return of.Offenders, nil
}

// ReadQueueDepth reports how many observations are queued without
// opening (and locking) the store.
func ReadQueueDepth(dataDir string) (int, error) {
	data, err := os.ReadFile(filepath.Join(dataDir, "queue.ndjson"))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read queue: %w", err)
	}
	count := 0
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line != "" {
			count++
		}
	}
	return count, nil
}
