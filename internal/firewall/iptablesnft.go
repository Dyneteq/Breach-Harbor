package firewall

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// iptables-nft constants. Distinct chain names from IPSet's
// (BREACHHARBOR/BREACHHARBOR6) even though both ultimately end up
// manipulating the same kernel nftables tables via the iptables-nft
// translation layer — Detect only ever picks one backend at a time,
// but distinct names keep Flush correctly scoped to just this
// backend's own rules if the choice of backend ever changes between
// runs (e.g. `ipset` gets installed later).
const (
	iptNFTChain4 = "BREACHHARBOR-NFT"
	iptNFTChain6 = "BREACHHARBOR-NFT6"
)

// IPTablesNFT implements Backend using the iptables-nft/ip6tables-nft
// command line tools directly — the nftables-backed implementation of
// the classic iptables CLI that Debian/Ubuntu ship as an explicit
// alternative to iptables-legacy (`update-alternatives --list
// iptables`). It exists alongside IPSet for one reason: IPSet requires
// the separate `ipset` package, which a minimal iptables-nft host
// often doesn't have installed, and would otherwise report itself
// unavailable and fall through past a perfectly usable iptables.
// Unlike IPSet, no ipset match extension is used — one DROP rule per
// blocked address goes directly into a dedicated chain, the same
// one-rule-per-address shape UFW uses. Deliberately invokes the
// *-nft-suffixed binaries by name rather than the bare `iptables`/
// `ip6tables` alternatives symlinks IPSet uses, so which underlying
// implementation this backend exercises never depends on whatever
// `update-alternatives --config iptables` last picked on the host.
type IPTablesNFT struct {
	run runner
}

// NewIPTablesNFT returns an IPTablesNFT backend. Pass nil to use the
// real system iptables-nft/ip6tables-nft binaries; tests pass a fake
// runner instead.
func NewIPTablesNFT(r runner) *IPTablesNFT {
	if r == nil {
		r = execRunner{}
	}
	return &IPTablesNFT{run: r}
}

func (b *IPTablesNFT) Name() string { return "iptables-nft" }

func (b *IPTablesNFT) Available(ctx context.Context) error {
	for _, bin := range []string{"iptables-nft", "ip6tables-nft"} {
		if _, err := b.run.LookPath(bin); err != nil {
			return fmt.Errorf("%s not found on PATH: %w", bin, err)
		}
	}
	if _, err := b.run.Run(ctx, "iptables-nft", "-S"); err != nil {
		return fmt.Errorf("iptables-nft is installed but not usable: %w", err)
	}
	return nil
}

func (b *IPTablesNFT) chainExists(ctx context.Context, bin, chain string) bool {
	_, err := b.run.Run(ctx, bin, "-L", chain, "-n")
	return err == nil
}

func (b *IPTablesNFT) ruleExists(ctx context.Context, bin string, args ...string) bool {
	_, err := b.run.Run(ctx, bin, append([]string{"-C"}, args...)...)
	return err == nil
}

func (b *IPTablesNFT) Init(ctx context.Context) error {
	if err := b.initFamily(ctx, "iptables-nft", iptNFTChain4); err != nil {
		return err
	}
	return b.initFamily(ctx, "ip6tables-nft", iptNFTChain6)
}

func (b *IPTablesNFT) initFamily(ctx context.Context, bin, chain string) error {
	if !b.chainExists(ctx, bin, chain) {
		if _, err := b.run.Run(ctx, bin, "-N", chain); err != nil {
			return fmt.Errorf("create chain %s: %w", chain, err)
		}
	}
	jumpArgs := []string{"INPUT", "-j", chain}
	if !b.ruleExists(ctx, bin, jumpArgs...) {
		if _, err := b.run.Run(ctx, bin, append([]string{"-I"}, jumpArgs...)...); err != nil {
			return fmt.Errorf("insert jump to %s: %w", chain, err)
		}
	}
	return nil
}

// familyFor returns which binary and dedicated chain a target belongs
// in, based on its address family — the same split nft/ipset make, but
// there's no shared set to add to here, just the per-family chain
// itself.
func (b *IPTablesNFT) familyFor(t Target) (bin, chain string) {
	if t.Addr.Addr().Is4() {
		return "iptables-nft", iptNFTChain4
	}
	return "ip6tables-nft", iptNFTChain6
}

func (b *IPTablesNFT) Block(ctx context.Context, targets []Target) error {
	for _, t := range targets {
		bin, chain := b.familyFor(t)
		args := []string{chain, "-s", t.Addr.Addr().String(), "-j", "DROP"}
		if b.ruleExists(ctx, bin, args...) {
			continue // already blocked — -A has no -exist equivalent, so check first
		}
		if _, err := b.run.Run(ctx, bin, append([]string{"-A"}, args...)...); err != nil {
			return fmt.Errorf("%s block %s: %w", bin, t.Addr, err)
		}
	}
	return nil
}

func (b *IPTablesNFT) Unblock(ctx context.Context, targets []Target) error {
	for _, t := range targets {
		bin, chain := b.familyFor(t)
		args := []string{chain, "-s", t.Addr.Addr().String(), "-j", "DROP"}
		if !b.ruleExists(ctx, bin, args...) {
			continue // already gone — -D errors on a rule that isn't there
		}
		if _, err := b.run.Run(ctx, bin, append([]string{"-D"}, args...)...); err != nil {
			return fmt.Errorf("%s unblock %s: %w", bin, t.Addr, err)
		}
	}
	return nil
}

func (b *IPTablesNFT) List(ctx context.Context) ([]Target, error) {
	var targets []Target
	for _, f := range []struct{ bin, chain string }{
		{"iptables-nft", iptNFTChain4},
		{"ip6tables-nft", iptNFTChain6},
	} {
		out, err := b.run.Run(ctx, f.bin, "-S", f.chain)
		if err != nil {
			// Chain not created yet (Init never called) — nothing blocked.
			continue
		}
		targets = append(targets, parseIPTablesDropRules(out)...)
	}
	return targets, nil
}

// parseIPTablesDropRules extracts addresses from `-A CHAIN -s <ip> -j
// DROP` lines in `iptables-nft -S <chain>` output.
func parseIPTablesDropRules(out []byte) []Target {
	var targets []Target
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "-A ") || !strings.Contains(line, "-j DROP") {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f != "-s" || i+1 >= len(fields) {
				continue
			}
			addrStr := fields[i+1]
			if p, err := netip.ParsePrefix(addrStr); err == nil {
				targets = append(targets, Target{Addr: p})
			} else if a, err := netip.ParseAddr(addrStr); err == nil {
				targets = append(targets, Target{Addr: netip.PrefixFrom(a, a.BitLen())})
			}
			break
		}
	}
	return targets
}

func (b *IPTablesNFT) Flush(ctx context.Context) error {
	if err := b.flushFamily(ctx, "iptables-nft", iptNFTChain4); err != nil {
		return err
	}
	return b.flushFamily(ctx, "ip6tables-nft", iptNFTChain6)
}

func (b *IPTablesNFT) flushFamily(ctx context.Context, bin, chain string) error {
	jumpArgs := []string{"INPUT", "-j", chain}
	if b.ruleExists(ctx, bin, jumpArgs...) {
		if _, err := b.run.Run(ctx, bin, append([]string{"-D"}, jumpArgs...)...); err != nil {
			return fmt.Errorf("remove jump from %s: %w", chain, err)
		}
	}
	if b.chainExists(ctx, bin, chain) {
		if _, err := b.run.Run(ctx, bin, "-F", chain); err != nil {
			return fmt.Errorf("flush chain %s: %w", chain, err)
		}
		if _, err := b.run.Run(ctx, bin, "-X", chain); err != nil {
			return fmt.Errorf("delete chain %s: %w", chain, err)
		}
	}
	return nil
}

// Status dumps the host's entire iptables-nft/ip6tables-nft ruleset —
// every chain, not just breach-harbor's own — so an operator can see
// the full picture this agent's rules sit inside of.
func (b *IPTablesNFT) Status(ctx context.Context) (string, error) {
	var out strings.Builder
	b.statusSection(ctx, &out, "iptables-nft -S", "iptables-nft", "-S")
	b.statusSection(ctx, &out, "ip6tables-nft -S", "ip6tables-nft", "-S")
	return out.String(), nil
}

func (b *IPTablesNFT) statusSection(ctx context.Context, out *strings.Builder, title, bin string, args ...string) {
	fmt.Fprintf(out, "# %s\n", title)
	section, err := b.run.Run(ctx, bin, args...)
	if err != nil {
		fmt.Fprintf(out, "(unavailable: %v)\n\n", err)
		return
	}
	out.Write(section)
	out.WriteString("\n")
}
