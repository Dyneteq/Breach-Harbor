package firewall

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// ufwComment tags every rule this backend adds so List/Unblock/Flush can
// tell a breach-harbor rule apart from the host's other ufw rules —
// ufw has no notion of a dedicated chain/table the way nft/ipset do, so
// a comment is the only thing scoping our changes to just our own.
const ufwComment = "breach-harbor"

// UFW implements Backend using the ufw(8) command line tool, a
// higher-level wrapper over iptables/ip6tables common on Debian/Ubuntu
// hosts that don't have ipset installed. Like PF, a single rule set
// holds both IPv4 and IPv6 addresses together (ufw picks the family
// from the address itself), so there's no need to split by family.
type UFW struct {
	run runner
}

// NewUFW returns a UFW backend. Pass nil to use the real system ufw
// binary; tests pass a fake runner instead.
func NewUFW(r runner) *UFW {
	if r == nil {
		r = execRunner{}
	}
	return &UFW{run: r}
}

func (b *UFW) Name() string { return "ufw" }

// Available reports whether ufw is installed and already active.
// Deliberately does NOT run `ufw enable` on the host's behalf: ufw's
// default policy denies incoming traffic, so enabling it on a box that
// hasn't already set up its own allow rules (SSH included) could lock
// out the very access needed to manage it. A host that wants
// breach-harbor to use ufw must have already run `ufw enable` itself.
func (b *UFW) Available(ctx context.Context) error {
	if _, err := b.run.LookPath("ufw"); err != nil {
		return fmt.Errorf("ufw not found on PATH: %w", err)
	}
	out, err := b.run.Run(ctx, "ufw", "status")
	if err != nil {
		return fmt.Errorf("ufw is installed but not usable: %w", err)
	}
	if !strings.Contains(string(out), "Status: active") {
		return fmt.Errorf("ufw is installed but not active (run `ufw enable` first — breach-harbor won't enable it for you)")
	}
	return nil
}

// Init is a no-op: unlike nft/ipset, ufw needs no dedicated table/chain
// created in advance — each Block call inserts a distinctly tagged rule
// directly, and Available already requires ufw to be active.
func (b *UFW) Init(ctx context.Context) error {
	return nil
}

func (b *UFW) Block(ctx context.Context, targets []Target) error {
	for _, t := range targets {
		args := []string{"--force", "insert", "1", "deny", "from", t.Addr.Addr().String(), "to", "any", "comment", ufwComment}
		if _, err := b.run.Run(ctx, "ufw", args...); err != nil {
			return fmt.Errorf("ufw insert %s: %w", t.Addr, err)
		}
	}
	return nil
}

func (b *UFW) Unblock(ctx context.Context, targets []Target) error {
	for _, t := range targets {
		args := []string{"--force", "delete", "deny", "from", t.Addr.Addr().String(), "to", "any", "comment", ufwComment}
		if _, err := b.run.Run(ctx, "ufw", args...); err != nil {
			return fmt.Errorf("ufw delete %s: %w", t.Addr, err)
		}
	}
	return nil
}

// List parses `ufw show added`, which prints every user rule as the raw
// `ufw` command that created it — a scriptable format, unlike `ufw
// status`'s column-aligned display. Only lines carrying our comment tag
// are ours; every other line is a rule some other tool or admin added,
// and is left alone.
func (b *UFW) List(ctx context.Context) ([]Target, error) {
	out, err := b.run.Run(ctx, "ufw", "show", "added")
	if err != nil {
		return nil, fmt.Errorf("ufw show added: %w", err)
	}
	return parseUFWShowAdded(out), nil
}

// parseUFWShowAdded extracts addresses from the "from" field of
// `ufw show added` lines tagged with our comment, e.g.:
//
//	ufw insert 1 deny from 203.0.113.44 to any comment breach-harbor
func parseUFWShowAdded(out []byte) []Target {
	var targets []Target
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasSuffix(line, "comment "+ufwComment) {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f != "from" || i+1 >= len(fields) {
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

// Status dumps `ufw status verbose` — every rule ufw is currently
// enforcing (SSH, other allowed ports, tailscale, etc.), not just the
// deny rules this agent has added — so an operator can see the whole
// picture this agent's blocks sit inside of. Verbose over the plain
// `status` form because it also reports the default incoming/outgoing
// policy and logging level, useful context for the same reason.
func (b *UFW) Status(ctx context.Context) (string, error) {
	out, err := b.run.Run(ctx, "ufw", "status", "verbose")
	if err != nil {
		return "", fmt.Errorf("ufw status verbose: %w", err)
	}
	return string(out), nil
}

// Flush removes every rule this backend ever added and nothing else.
// ufw has no single command to drop "every rule with this comment", so
// Flush lists its own tagged rules and unblocks each in turn — safe to
// call even if nothing was ever blocked (List then returns nothing).
func (b *UFW) Flush(ctx context.Context) error {
	targets, err := b.List(ctx)
	if err != nil {
		return err
	}
	return b.Unblock(ctx, targets)
}
