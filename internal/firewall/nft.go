package firewall

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// nftables constants. Everything this backend creates lives inside a
// single dedicated table, so Flush can delete just that table.
const (
	nftFamily = "inet"
	nftTable  = "breachharbor"
	nftChain  = "input"
	nftSet4   = "blocked4"
	nftSet6   = "blocked6"
)

// NFTables implements Backend using the nft(8) command line tool.
type NFTables struct {
	run runner
}

// NewNFTables returns an NFTables backend. Pass nil to use the real
// system nft binary; tests pass a fake runner instead.
func NewNFTables(r runner) *NFTables {
	if r == nil {
		r = execRunner{}
	}
	return &NFTables{run: r}
}

func (b *NFTables) Name() string { return "nftables" }

func (b *NFTables) Available(ctx context.Context) error {
	path, err := b.run.LookPath("nft")
	if err != nil {
		return fmt.Errorf("nft not found on PATH: %w", err)
	}
	if _, err := b.run.Run(ctx, path, "list", "tables"); err != nil {
		return fmt.Errorf("nft is installed but not usable: %w", err)
	}
	return nil
}

func (b *NFTables) tableExists(ctx context.Context) bool {
	_, err := b.run.Run(ctx, "nft", "list", "table", nftFamily, nftTable)
	return err == nil
}

func (b *NFTables) Init(ctx context.Context) error {
	if b.tableExists(ctx) {
		return nil
	}
	cmds := [][]string{
		{"add", "table", nftFamily, nftTable},
		{"add", "set", nftFamily, nftTable, nftSet4, "{", "type", "ipv4_addr;", "flags", "interval;", "}"},
		{"add", "set", nftFamily, nftTable, nftSet6, "{", "type", "ipv6_addr;", "flags", "interval;", "}"},
		{"add", "chain", nftFamily, nftTable, nftChain, "{", "type", "filter;", "hook", "input;", "priority", "0;", "policy", "accept;", "}"},
		{"add", "rule", nftFamily, nftTable, nftChain, "ip", "saddr", "@" + nftSet4, "drop"},
		{"add", "rule", nftFamily, nftTable, nftChain, "ip6", "saddr", "@" + nftSet6, "drop"},
	}
	for _, args := range cmds {
		if _, err := b.run.Run(ctx, "nft", args...); err != nil {
			return fmt.Errorf("nft init failed at %q: %w", strings.Join(args, " "), err)
		}
	}
	return nil
}

func splitByFamily(targets []Target) (v4, v6 []netip.Prefix) {
	for _, t := range targets {
		if t.Addr.Addr().Is4() {
			v4 = append(v4, t.Addr)
		} else {
			v6 = append(v6, t.Addr)
		}
	}
	return v4, v6
}

func elementList(prefixes []netip.Prefix) string {
	parts := make([]string, len(prefixes))
	for i, p := range prefixes {
		parts[i] = p.String()
	}
	return strings.Join(parts, ", ")
}

func (b *NFTables) Block(ctx context.Context, targets []Target) error {
	if len(targets) == 0 {
		return nil
	}
	v4, v6 := splitByFamily(targets)
	if len(v4) > 0 {
		if _, err := b.run.Run(ctx, "nft", "add", "element", nftFamily, nftTable, nftSet4, "{", elementList(v4), "}"); err != nil {
			return fmt.Errorf("nft block (ipv4): %w", err)
		}
	}
	if len(v6) > 0 {
		if _, err := b.run.Run(ctx, "nft", "add", "element", nftFamily, nftTable, nftSet6, "{", elementList(v6), "}"); err != nil {
			return fmt.Errorf("nft block (ipv6): %w", err)
		}
	}
	return nil
}

func (b *NFTables) Unblock(ctx context.Context, targets []Target) error {
	if len(targets) == 0 {
		return nil
	}
	v4, v6 := splitByFamily(targets)
	if len(v4) > 0 {
		if _, err := b.run.Run(ctx, "nft", "delete", "element", nftFamily, nftTable, nftSet4, "{", elementList(v4), "}"); err != nil {
			return fmt.Errorf("nft unblock (ipv4): %w", err)
		}
	}
	if len(v6) > 0 {
		if _, err := b.run.Run(ctx, "nft", "delete", "element", nftFamily, nftTable, nftSet6, "{", elementList(v6), "}"); err != nil {
			return fmt.Errorf("nft unblock (ipv6): %w", err)
		}
	}
	return nil
}

func (b *NFTables) List(ctx context.Context) ([]Target, error) {
	var targets []Target
	for _, set := range []string{nftSet4, nftSet6} {
		out, err := b.run.Run(ctx, "nft", "list", "set", nftFamily, nftTable, set)
		if err != nil {
			// Set not created yet (Init never called) — nothing blocked.
			continue
		}
		targets = append(targets, parseNFTSetElements(out)...)
	}
	return targets, nil
}

// parseNFTSetElements extracts addresses from an "elements = { a, b, c }"
// line in `nft list set` output.
func parseNFTSetElements(out []byte) []Target {
	var targets []Target
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "elements") {
			continue
		}
		start := strings.Index(line, "{")
		end := strings.LastIndex(line, "}")
		if start == -1 || end == -1 || end <= start {
			continue
		}
		for _, raw := range strings.Split(line[start+1:end], ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			if p, err := netip.ParsePrefix(raw); err == nil {
				targets = append(targets, Target{Addr: p})
			} else if a, err := netip.ParseAddr(raw); err == nil {
				targets = append(targets, Target{Addr: netip.PrefixFrom(a, a.BitLen())})
			}
		}
	}
	return targets
}

func (b *NFTables) Flush(ctx context.Context) error {
	if !b.tableExists(ctx) {
		return nil
	}
	if _, err := b.run.Run(ctx, "nft", "delete", "table", nftFamily, nftTable); err != nil {
		return fmt.Errorf("nft flush: %w", err)
	}
	return nil
}

// Status dumps the host's entire nftables ruleset — every table, not
// just breach-harbor's own — so an operator can see the full picture
// this agent's rules sit inside of.
func (b *NFTables) Status(ctx context.Context) (string, error) {
	out, err := b.run.Run(ctx, "nft", "list", "ruleset")
	if err != nil {
		return "", fmt.Errorf("nft list ruleset: %w", err)
	}
	return string(out), nil
}
