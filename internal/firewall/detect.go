package firewall

import (
	"context"
	"errors"
	"fmt"
)

// Detect picks a firewall backend to use. If prefer names a specific
// backend ("nft"/"nftables" or "ipset"/"iptables"), that backend is
// required and an error is returned if it isn't usable. If prefer is ""
// or "auto", nftables is tried first, then iptables/ipset, and an error
// is returned only if neither is usable.
func Detect(ctx context.Context, prefer string) (Backend, error) {
	var candidates []Backend
	switch prefer {
	case "", "auto":
		candidates = []Backend{NewNFTables(nil), NewIPSet(nil)}
	case "nft", "nftables":
		candidates = []Backend{NewNFTables(nil)}
	case "ipset", "iptables":
		candidates = []Backend{NewIPSet(nil)}
	default:
		return nil, fmt.Errorf("unknown firewall backend %q (want nft, ipset, or auto)", prefer)
	}

	var errs []error
	for _, b := range candidates {
		if err := b.Available(ctx); err == nil {
			return b, nil
		} else {
			errs = append(errs, fmt.Errorf("%s: %w", b.Name(), err))
		}
	}
	return nil, fmt.Errorf("no usable firewall backend found (install nftables or iptables+ipset): %w", errors.Join(errs...))
}
