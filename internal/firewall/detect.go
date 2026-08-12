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
// backend ("nft"/"nftables", "ipset"/"iptables", "iptables-nft", "ufw",
// or "pf"), that backend is required and an error is returned if it
// isn't usable. If prefer is "" or "auto", nftables is tried first,
// then iptables+ipset, then iptables-nft, then ufw, then — on macOS/
// OpenBSD only — pf, and an error is returned only if none is usable.
// iptables-nft sits between ipset and ufw: IPSet additionally requires
// the separate `ipset` package, which a minimal iptables-nft host
// (increasingly the Debian/Ubuntu default) often doesn't have, so
// iptables-nft is the fallback that needs nothing but iptables-nft/
// ip6tables-nft themselves; ufw (which needs to already be active —
// see UFW.Available) is the fallback after that. "iptables" (bare)
// keeps meaning the ipset-backed combo, for compatibility with configs
// written before iptables-nft existed — "iptables-nft" is the only
// spelling for the new ipset-free backend.
func Detect(ctx context.Context, prefer string) (Backend, error) {
	var candidates []Backend
	switch prefer {
	case "", "auto":
		candidates = []Backend{NewNFTables(nil), NewIPSet(nil), NewIPTablesNFT(nil), NewUFW(nil)}
		if pfPlatforms[runtime.GOOS] {
			candidates = append(candidates, NewPF(nil))
		}
	case "nft", "nftables":
		candidates = []Backend{NewNFTables(nil)}
	case "ipset", "iptables":
		candidates = []Backend{NewIPSet(nil)}
	case "iptables-nft":
		candidates = []Backend{NewIPTablesNFT(nil)}
	case "ufw":
		candidates = []Backend{NewUFW(nil)}
	case "pf":
		candidates = []Backend{NewPF(nil)}
	default:
		return nil, fmt.Errorf("unknown firewall backend %q (want nft, ipset, iptables-nft, ufw, pf, or auto)", prefer)
	}

	var errs []error
	for _, b := range candidates {
		if err := b.Available(ctx); err == nil {
			return b, nil
		} else {
			errs = append(errs, fmt.Errorf("%s: %w", b.Name(), err))
		}
	}
	return nil, fmt.Errorf("no usable firewall backend found (install nftables, or iptables+ipset, or iptables-nft, or run `ufw enable`, on Linux, or use pfctl on macOS/OpenBSD): %w", errors.Join(errs...))
}
