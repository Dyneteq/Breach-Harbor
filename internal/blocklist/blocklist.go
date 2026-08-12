// Package blocklist is the signed, versioned list of IPs the server
// publishes and enrolled agents fetch — the concrete type behind
// PLAN.md's "cache first, ask later" design: an agent only ever
// replaces its on-disk copy after a successful signature verification
// (fetch.go), and keeps enforcing the last-good one indefinitely if the
// server is unreachable.
package blocklist

import (
	"encoding/json"
	"net/netip"
	"time"
)

// Entry is one blocked range in a published blocklist.
type Entry struct {
	Prefix netip.Prefix `json:"prefix"`
	Reason string       `json:"reason"`
}

// Blocklist is the signed payload itself. Version increments on every
// publish so an agent can tell whether a fetch actually changed
// anything without diffing the entry list.
type Blocklist struct {
	Version     int           `json:"version"`
	GeneratedAt time.Time     `json:"generated_at"`
	TTL         time.Duration `json:"ttl"`
	Entries     []Entry       `json:"entries"`
}

// SignedBlocklist is the wire format for GET /v1/blocklist: the
// blocklist, its ed25519 signature, and the public key it verifies
// against (bare TOFU for M2 — PLAN.md's M3 sketch adds pinning/
// rotation on top of this).
type SignedBlocklist struct {
	Blocklist Blocklist `json:"blocklist"`
	Signature []byte    `json:"signature"`
	PublicKey []byte    `json:"public_key"`
}

// canonical returns a deterministic byte encoding of bl for
// signing/verification. Blocklist has no maps, so encoding/json's
// fixed struct-field order already makes this stable across calls.
func (bl Blocklist) canonical() ([]byte, error) {
	return json.Marshal(bl)
}
