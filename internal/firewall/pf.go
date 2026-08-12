package firewall

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// pf constants. Everything this backend creates lives inside a single
// dedicated anchor and table, so Flush can remove just those without
// touching any other pf rules already on the host (macOS's own
// Application Firewall, a VPN client, or the user's own /etc/pf.conf).
const (
	pfAnchor = "breach-harbor"
	pfTable  = "bh-blocked"
)

// PF implements Backend using the pfctl(8) command line tool, for
// macOS and OpenBSD (and, in principle, other pf-based BSDs — only
// macOS and OpenBSD are exercised here). Unlike nft/ipset, a single pf
// table holds both IPv4 and IPv6 addresses together, so there's no
// need to split by family.
type PF struct {
	run runner
}

// NewPF returns a PF backend. Pass nil to use the real system pfctl
// binary; tests pass a fake runner instead.
func NewPF(r runner) *PF {
	if r == nil {
		r = execRunner{}
	}
	return &PF{run: r}
}

func (b *PF) Name() string { return "pf" }

func (b *PF) Available(ctx context.Context) error {
	if _, err := b.run.LookPath("pfctl"); err != nil {
		return fmt.Errorf("pfctl not found on PATH: %w", err)
	}
	if _, err := b.run.Run(ctx, "pfctl", "-s", "info"); err != nil {
		return fmt.Errorf("pfctl is installed but not usable: %w", err)
	}
	return nil
}

// anchorLoaded reports whether the breach-harbor anchor's table has
// already been loaded, i.e. whether Init has already run.
func (b *PF) anchorLoaded(ctx context.Context) bool {
	_, err := b.run.Run(ctx, "pfctl", "-a", pfAnchor, "-t", pfTable, "-T", "show")
	return err == nil
}

func (b *PF) enabled(ctx context.Context) (bool, error) {
	out, err := b.run.Run(ctx, "pfctl", "-s", "info")
	if err != nil {
		return false, err
	}
	return strings.Contains(string(out), "Status: Enabled"), nil
}

// Init is idempotent: it enables pf only if pf is currently disabled
// (never touches an already-enabled pf, so other rulesets aren't
// disrupted), then loads the breach-harbor anchor's table + block rule
// if it isn't loaded yet. Loading uses `pfctl -a <anchor> -f -` with
// the ruleset on stdin — the same technique other macOS firewall tools
// use to attach a named anchor without editing /etc/pf.conf.
func (b *PF) Init(ctx context.Context) error {
	on, err := b.enabled(ctx)
	if err != nil {
		return fmt.Errorf("pf status check: %w", err)
	}
	if !on {
		if _, err := b.run.Run(ctx, "pfctl", "-e"); err != nil {
			return fmt.Errorf("enable pf: %w", err)
		}
	}
	if b.anchorLoaded(ctx) {
		return nil
	}
	rules := fmt.Sprintf("table <%s> persist\nblock in quick from <%s>\n", pfTable, pfTable)
	if _, err := b.run.RunStdin(ctx, rules, "pfctl", "-a", pfAnchor, "-f", "-"); err != nil {
		return fmt.Errorf("load %s anchor: %w", pfAnchor, err)
	}
	return nil
}

func (b *PF) Block(ctx context.Context, targets []Target) error {
	for _, t := range targets {
		if _, err := b.run.Run(ctx, "pfctl", "-a", pfAnchor, "-t", pfTable, "-T", "add", t.Addr.Addr().String()); err != nil {
			return fmt.Errorf("pfctl table add %s: %w", t.Addr, err)
		}
	}
	return nil
}

func (b *PF) Unblock(ctx context.Context, targets []Target) error {
	for _, t := range targets {
		if _, err := b.run.Run(ctx, "pfctl", "-a", pfAnchor, "-t", pfTable, "-T", "delete", t.Addr.Addr().String()); err != nil {
			return fmt.Errorf("pfctl table delete %s: %w", t.Addr, err)
		}
	}
	return nil
}

func (b *PF) List(ctx context.Context) ([]Target, error) {
	out, err := b.run.Run(ctx, "pfctl", "-a", pfAnchor, "-t", pfTable, "-T", "show")
	if err != nil {
		// Table not loaded yet (Init never called) — nothing blocked.
		return nil, nil
	}
	return parsePFTableShow(out), nil
}

// parsePFTableShow extracts addresses from `pfctl -t <table> -T show`
// output: one address (occasionally CIDR) per line, sometimes leading
// whitespace.
func parsePFTableShow(out []byte) []Target {
	var targets []Target
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if p, err := netip.ParsePrefix(line); err == nil {
			targets = append(targets, Target{Addr: p})
		} else if a, err := netip.ParseAddr(line); err == nil {
			targets = append(targets, Target{Addr: netip.PrefixFrom(a, a.BitLen())})
		}
	}
	return targets
}

// Flush removes only the breach-harbor anchor's rules and table — it
// must never call `pfctl -d`, since other things on the host (macOS's
// Application Firewall, a VPN client, the user's own pf.conf) may
// depend on pf staying enabled. Safe to call even if Init was never
// run.
func (b *PF) Flush(ctx context.Context) error {
	if !b.anchorLoaded(ctx) {
		return nil
	}
	if _, err := b.run.Run(ctx, "pfctl", "-a", pfAnchor, "-F", "rules"); err != nil {
		return fmt.Errorf("flush %s rules: %w", pfAnchor, err)
	}
	if _, err := b.run.Run(ctx, "pfctl", "-a", pfAnchor, "-t", pfTable, "-T", "kill"); err != nil {
		return fmt.Errorf("remove %s table: %w", pfTable, err)
	}
	return nil
}
