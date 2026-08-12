// Package store holds the standalone agent's local, file-backed
// state. This is deliberately not GORM/sqlite (that's the server's
// store, internal/services + internal/models) — a standalone agent
// must never require a database just to start blocking things.
package store

import (
	"net/netip"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/blocklist"
)

// Offender is one IP the agent has observed and scored. Score is the
// live, windowed value (see internal/agent/offender.go); Events is
// the lifetime observation count, which never decays.
type Offender struct {
	IP        netip.Addr `json:"ip"`
	Score     int        `json:"score"`
	Events    int        `json:"events"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
	Sources   []string   `json:"sources"`
	Blocked   bool       `json:"blocked"`
	BlockedAt *time.Time `json:"blocked_at,omitempty"`
}

// Observation is one raw event queued for upload to a server once the
// agent is enrolled (internal/agent/enroll.go, M2). In standalone mode
// nothing ever drains this queue — Enqueue still bounds it so a
// standalone agent's disk usage never grows without limit.
type Observation struct {
	ID       string            `json:"id"`
	IP       netip.Addr        `json:"ip"`
	Kind     string            `json:"kind"`
	Time     time.Time         `json:"time"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// AgentStore is the standalone agent's local persistence. A single
// FileStore implementation lives in filestore.go; the interface exists
// so internal/agent can be tested against a fake.
type AgentStore interface {
	GetOffender(ip netip.Addr) (Offender, bool, error)
	PutOffender(o Offender) error
	ListOffenders() ([]Offender, error)
	DeleteOffender(ip netip.Addr) error

	// Enqueue never blocks and never grows the queue unbounded — it
	// drops the oldest entries once MaxQueueEntries is exceeded.
	Enqueue(obs Observation) error
	Dequeue(max int) ([]Observation, error)
	Ack(ids []string) error
	QueueDepth() (int, error)

	Close() error

	// SaveBlocklist persists the full signed blocklist (not just its
	// entries) so a later re-verify is possible without re-fetching —
	// LoadBlocklist reports found=false on a fresh data dir with
	// nothing cached yet, never an error.
	SaveBlocklist(bl blocklist.SignedBlocklist) error
	LoadBlocklist() (bl blocklist.SignedBlocklist, found bool, err error)
}
