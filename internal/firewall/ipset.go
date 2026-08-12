package firewall

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// ipset/iptables constants. Everything this backend creates is named
// distinctly (bh-blocked*, BREACHHARBOR*) so Flush can remove exactly
// what it added.
const (
	ipsetSet4 = "bh-blocked4"
	ipsetSet6 = "bh-blocked6"
	ipsChain4 = "BREACHHARBOR"
	ipsChain6 = "BREACHHARBOR6"
)

// IPSet implements Backend using the iptables/ip6tables + ipset command
// line tools, for hosts without nftables.
type IPSet struct {
	run runner
}

// NewIPSet returns an IPSet backend. Pass nil to use the real system
// binaries; tests pass a fake runner instead.
func NewIPSet(r runner) *IPSet {
	if r == nil {
		r = execRunner{}
	}
	return &IPSet{run: r}
}

func (b *IPSet) Name() string { return "ipset" }

func (b *IPSet) Available(ctx context.Context) error {
	for _, bin := range []string{"iptables", "ip6tables", "ipset"} {
		if _, err := b.run.LookPath(bin); err != nil {
			return fmt.Errorf("%s not found on PATH: %w", bin, err)
		}
	}
	if _, err := b.run.Run(ctx, "ipset", "-v"); err != nil {
		return fmt.Errorf("ipset is installed but not usable: %w", err)
	}
	return nil
}

func (b *IPSet) setExists(ctx context.Context, set string) bool {
	_, err := b.run.Run(ctx, "ipset", "list", set, "-name")
	return err == nil
}

func (b *IPSet) chainExists(ctx context.Context, table, chain string) bool {
	_, err := b.run.Run(ctx, table, "-L", chain, "-n")
	return err == nil
}

func (b *IPSet) ruleExists(ctx context.Context, table string, args ...string) bool {
	_, err := b.run.Run(ctx, table, append([]string{"-C"}, args...)...)
	return err == nil
}

func (b *IPSet) Init(ctx context.Context) error {
	if !b.setExists(ctx, ipsetSet4) {
		if _, err := b.run.Run(ctx, "ipset", "create", ipsetSet4, "hash:ip", "family", "inet", "-exist"); err != nil {
			return fmt.Errorf("create ipset %s: %w", ipsetSet4, err)
		}
	}
	if !b.setExists(ctx, ipsetSet6) {
		if _, err := b.run.Run(ctx, "ipset", "create", ipsetSet6, "hash:ip", "family", "inet6", "-exist"); err != nil {
			return fmt.Errorf("create ipset %s: %w", ipsetSet6, err)
		}
	}
	if err := b.initFamily(ctx, "iptables", ipsChain4, ipsetSet4); err != nil {
		return err
	}
	if err := b.initFamily(ctx, "ip6tables", ipsChain6, ipsetSet6); err != nil {
		return err
	}
	return nil
}

func (b *IPSet) initFamily(ctx context.Context, table, chain, set string) error {
	if !b.chainExists(ctx, table, chain) {
		if _, err := b.run.Run(ctx, table, "-N", chain); err != nil {
			return fmt.Errorf("create chain %s: %w", chain, err)
		}
	}
	dropArgs := []string{chain, "-m", "set", "--match-set", set, "src", "-j", "DROP"}
	if !b.ruleExists(ctx, table, dropArgs...) {
		if _, err := b.run.Run(ctx, table, append([]string{"-A"}, dropArgs...)...); err != nil {
			return fmt.Errorf("append drop rule to %s: %w", chain, err)
		}
	}
	jumpArgs := []string{"INPUT", "-j", chain}
	if !b.ruleExists(ctx, table, jumpArgs...) {
		if _, err := b.run.Run(ctx, table, append([]string{"-I"}, jumpArgs...)...); err != nil {
			return fmt.Errorf("insert jump to %s: %w", chain, err)
		}
	}
	return nil
}

func (b *IPSet) Block(ctx context.Context, targets []Target) error {
	for _, t := range targets {
		set := ipsetSet4
		if !t.Addr.Addr().Is4() {
			set = ipsetSet6
		}
		if _, err := b.run.Run(ctx, "ipset", "add", set, t.Addr.Addr().String(), "-exist"); err != nil {
			return fmt.Errorf("ipset add %s %s: %w", set, t.Addr, err)
		}
	}
	return nil
}

func (b *IPSet) Unblock(ctx context.Context, targets []Target) error {
	for _, t := range targets {
		set := ipsetSet4
		if !t.Addr.Addr().Is4() {
			set = ipsetSet6
		}
		if _, err := b.run.Run(ctx, "ipset", "del", set, t.Addr.Addr().String(), "-exist"); err != nil {
			return fmt.Errorf("ipset del %s %s: %w", set, t.Addr, err)
		}
	}
	return nil
}

func (b *IPSet) List(ctx context.Context) ([]Target, error) {
	var targets []Target
	for _, set := range []string{ipsetSet4, ipsetSet6} {
		out, err := b.run.Run(ctx, "ipset", "list", set, "-output", "save")
		if err != nil {
			// Set not created yet (Init never called) — nothing blocked.
			continue
		}
		targets = append(targets, parseIPSetSave(set, out)...)
	}
	return targets, nil
}

// parseIPSetSave extracts addresses from `ipset list <set> -output save`
// lines of the form "add <set> <ip>".
func parseIPSetSave(set string, out []byte) []Target {
	var targets []Target
	prefix := "add " + set + " "
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		addrStr := strings.TrimSpace(strings.TrimPrefix(line, prefix))
		if a, err := netip.ParseAddr(addrStr); err == nil {
			targets = append(targets, Target{Addr: netip.PrefixFrom(a, a.BitLen())})
		}
	}
	return targets
}

func (b *IPSet) Flush(ctx context.Context) error {
	if err := b.flushFamily(ctx, "iptables", ipsChain4, ipsetSet4); err != nil {
		return err
	}
	if err := b.flushFamily(ctx, "ip6tables", ipsChain6, ipsetSet6); err != nil {
		return err
	}
	return nil
}

// Status dumps the host's entire iptables/ip6tables ruleset plus every
// ipset set — not just breach-harbor's own chains and sets — so an
// operator can see the full picture this agent's rules sit inside of.
// Each section is best-effort: a family or tool that errors (e.g. no
// IPv6 support compiled in) is noted inline rather than failing the
// whole dump.
func (b *IPSet) Status(ctx context.Context) (string, error) {
	var out strings.Builder
	b.statusSection(ctx, &out, "iptables -S", "iptables", "-S")
	b.statusSection(ctx, &out, "ip6tables -S", "ip6tables", "-S")
	b.statusSection(ctx, &out, "ipset list", "ipset", "list")
	return out.String(), nil
}

func (b *IPSet) statusSection(ctx context.Context, out *strings.Builder, title, name string, args ...string) {
	fmt.Fprintf(out, "# %s\n", title)
	section, err := b.run.Run(ctx, name, args...)
	if err != nil {
		fmt.Fprintf(out, "(unavailable: %v)\n\n", err)
		return
	}
	out.Write(section)
	out.WriteString("\n")
}

func (b *IPSet) flushFamily(ctx context.Context, table, chain, set string) error {
	jumpArgs := []string{"INPUT", "-j", chain}
	if b.ruleExists(ctx, table, jumpArgs...) {
		if _, err := b.run.Run(ctx, table, append([]string{"-D"}, jumpArgs...)...); err != nil {
			return fmt.Errorf("remove jump from %s: %w", chain, err)
		}
	}
	if b.chainExists(ctx, table, chain) {
		if _, err := b.run.Run(ctx, table, "-F", chain); err != nil {
			return fmt.Errorf("flush chain %s: %w", chain, err)
		}
		if _, err := b.run.Run(ctx, table, "-X", chain); err != nil {
			return fmt.Errorf("delete chain %s: %w", chain, err)
		}
	}
	if b.setExists(ctx, set) {
		if _, err := b.run.Run(ctx, "ipset", "destroy", set); err != nil {
			return fmt.Errorf("destroy ipset %s: %w", set, err)
		}
	}
	return nil
}
