package firewall

import (
	"context"
	"errors"
	"fmt"
	"runtime"
)

// pfPlatforms are the GOOS values on which the "auto" path considers
// PF a candidate. Explicit `--firewall pf` bypasses this gate and is
// tried on any OS (same permissive behavior as forcing nft/ipset on
// the "wrong" platform: Available() simply fails cleanly).
var pfPlatforms = map[string]bool{"darwin": true, "openbsd": true}

// Detect picks a firewall backend to use. If prefer names a specific
// backend ("nft"/"nftables", "ipset"/"iptables", or "pf"), that
// backend is required and an error is returned if it isn't usable. If
// prefer is "" or "auto", nftables is tried first, then iptables/
// ipset, then — on macOS/OpenBSD only — pf, and an error is returned
// only if none is usable.
func Detect(ctx context.Context, prefer string) (Backend, error) {
	var candidates []Backend
	switch prefer {
	case "", "auto":
		candidates = []Backend{NewNFTables(nil), NewIPSet(nil)}
		if pfPlatforms[runtime.GOOS] {
			candidates = append(candidates, NewPF(nil))
		}
	case "nft", "nftables":
		candidates = []Backend{NewNFTables(nil)}
	case "ipset", "iptables":
		candidates = []Backend{NewIPSet(nil)}
	case "pf":
		candidates = []Backend{NewPF(nil)}
	default:
		return nil, fmt.Errorf("unknown firewall backend %q (want nft, ipset, pf, or auto)", prefer)
	}

	var errs []error
	for _, b := range candidates {
		if err := b.Available(ctx); err == nil {
			return b, nil
		} else {
			errs = append(errs, fmt.Errorf("%s: %w", b.Name(), err))
		}
	}
	return nil, fmt.Errorf("no usable firewall backend found (install nftables or iptables+ipset on Linux, or use pfctl on macOS/OpenBSD): %w", errors.Join(errs...))
}
