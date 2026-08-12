// Package firewall provides a pluggable interface over the host's
// firewall so the agent can block and unblock IP addresses without the
// rest of the codebase caring whether nftables, iptables/ipset, or
// (on macOS/OpenBSD) pf is in use. Every Backend confines its changes
// to a single, clearly named table/chain/set/anchor so Flush can
// remove exactly what this agent added and never touch a rule the
// user created themselves.
package firewall

import (
	"context"
	"net/netip"
)

// Target is a single address this agent has decided to block or unblock.
type Target struct {
	Addr netip.Prefix
}

// Backend is a pluggable firewall implementation.
type Backend interface {
	// Name is a short identifier, e.g. "nftables" or "ipset".
	Name() string

	// Available reports whether this backend's binaries and kernel
	// features are present. It must not require root and must not
	// mutate any system state.
	Available(ctx context.Context) error

	// Init creates the dedicated table/chain/set if it doesn't already
	// exist. Idempotent. Only called when enforcement is turned on —
	// a dry-run agent never calls Init.
	Init(ctx context.Context) error

	// Block adds targets to the dedicated blocked set.
	Block(ctx context.Context, targets []Target) error

	// Unblock removes targets from the dedicated blocked set.
	Unblock(ctx context.Context, targets []Target) error

	// List returns every target currently blocked by this backend.
	List(ctx context.Context) ([]Target, error)

	// Flush removes the entire dedicated table/chain/set — every rule
	// this backend ever added, and nothing else. Safe to call even if
	// Init was never called (no-op) or the agent isn't currently
	// running.
	Flush(ctx context.Context) error

	// Status returns a raw, human-readable dump of the host's entire
	// current ruleset for this backend — not just the addresses List
	// reports, but every rule in effect, including ones this agent
	// never added (an admin's SSH allow rule, another tool's chain,
	// etc.). Read-only, purely for display/diagnostics; never mutates
	// state and is never consulted for enforcement decisions.
	Status(ctx context.Context) (string, error)
}
