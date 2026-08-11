package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Config is the standalone agent's configuration. It is a plain,
// flag-library-agnostic struct — internal/cli's *_cmd.go files own
// flag parsing and populate one of these; internal/agent never
// imports "flag" so a future file-based loader (PLAN.md's --config,
// still unimplemented in M1) can populate the same struct without
// touching flags at all.
type Config struct {
	DataDir string
	Enforce bool
	// Sources restricts which logsource.Source names to watch; empty
	// means "every detected source" — the zero-config default.
	Sources []string
	// Server is the M2 enrollment placeholder; empty means standalone
	// (no server, cache-first local operation only).
	Server string
	// Feeds maps a feed.Provider name to whether it's enabled. A
	// missing entry defaults to enabled — only an explicit "off"
	// (--feed spamhaus=off) turns one off.
	Feeds        map[string]bool
	AbuseIPDBKey string
	// Refresh is how often feeds are re-fetched (bounded further by
	// each feed's own on-disk TTL cache — see internal/feed/cache.go).
	Refresh time.Duration
	// Firewall selects a backend name ("auto", "nft", or "ipset"),
	// passed straight through to firewall.Detect.
	Firewall string
	JSON     bool
}

// Default returns the zero-config defaults: `breachharbor agent run`
// with no flags at all must be a genuinely useful, safe (dry-run)
// standalone agent.
func Default() Config {
	return Config{
		DataDir:  DefaultDataDir(),
		Enforce:  false,
		Refresh:  15 * time.Minute,
		Firewall: "auto",
	}
}

// Validate reports the first configuration problem found, if any.
func (c Config) Validate() error {
	if c.DataDir == "" {
		return fmt.Errorf("data directory must not be empty")
	}
	if c.Refresh <= 0 {
		return fmt.Errorf("refresh interval must be positive, got %s", c.Refresh)
	}
	switch c.Firewall {
	case "auto", "nft", "nftables", "ipset", "iptables":
	default:
		return fmt.Errorf("unknown firewall backend %q (want auto, nft, or ipset)", c.Firewall)
	}
	return nil
}

// FeedEnabled reports whether the named feed provider should run,
// honoring the Feeds map's opt-out semantics (missing = enabled).
func (c Config) FeedEnabled(name string) bool {
	if c.Feeds == nil {
		return true
	}
	enabled, set := c.Feeds[name]
	if !set {
		return true
	}
	return enabled
}

// DefaultDataDir is the single definition of where agent state lives
// by default: a system path when root, a per-user path otherwise.
// `breachharbor doctor` and `agent run --data-dir`'s default both call
// into this rather than keeping their own copy.
func DefaultDataDir() string {
	if os.Geteuid() == 0 {
		return "/var/lib/breachharbor"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "breachharbor")
	}
	return filepath.Join(home, ".local", "state", "breachharbor")
}
