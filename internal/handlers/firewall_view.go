package handlers

import (
	"sort"
	"strings"

	"github.com/Dyneteq/Breach-Harbor/internal/models"
)

// FirewallRule is one parsed row from a `ufw status verbose` listing —
// currently the only backend whose Status() dump this package knows
// how to turn into a table; nftables/ipset/pf collectors fall back to
// FirewallView's raw text.
type FirewallRule struct {
	To     string
	Action string // e.g. "ALLOW IN", "DENY IN" — the raw column text, kept verbatim for display
	From   string
	// Class buckets Action for the template's badge color: "allow",
	// "deny", "reject", "limit", or "other" for anything unrecognized.
	Class string
	IPv6  bool
	// OwnRule marks a row whose From matches one of this collector's
	// own FirewallBlockedIPs — i.e. a rule breach-harbor itself added,
	// as opposed to one the admin (or another tool) put there.
	OwnRule bool
}

// FirewallView is collector_firewall.html's presentation model.
type FirewallView struct {
	Collector models.Collector
	// Kind selects which structured section the template renders:
	// "ufw", "nftables", or "" (unsupported backend / no report yet /
	// a dump this parser couldn't make sense of) — "" falls back to
	// showing Collector.FirewallConfig as raw text.
	Kind string
	// Structured is Kind != "" — kept alongside Kind so the template's
	// existing boolean checks don't all need rewriting to string
	// comparisons.
	Structured bool

	// ufw fields.
	UFWStatus     string
	DefaultPolicy string
	Logging       string
	Rules         []FirewallRule
	OpenPorts     []string
	AllowCount    int
	DenyCount     int
	OtherCount    int

	// nftables fields.
	NFTables   []NFTable
	TotalRules int // sum of Rules across every table/chain, for the stat tile
}

// BuildFirewallView turns a collector's raw FirewallConfig dump into a
// structured, displayable view. Only "ufw" and "nftables" are parsed
// today — ipset/iptables-nft/pf dumps are free-form enough (several
// concatenated command outputs, a BSD-specific rule syntax) that a
// naive parse would misrepresent them; showing their raw text plainly
// beats a wrong table.
func BuildFirewallView(c models.Collector) FirewallView {
	view := FirewallView{Collector: c}
	if strings.TrimSpace(c.FirewallConfig) == "" {
		return view
	}

	switch c.FirewallBackend {
	case "ufw":
		buildUFWView(&view, c)
	case "nftables":
		buildNFTablesView(&view, c)
	}
	return view
}

func buildUFWView(view *FirewallView, c models.Collector) {
	rules, status, defaultPolicy, logging := parseUFWStatusVerbose(c.FirewallConfig, c.FirewallBlockedIPs)
	if len(rules) == 0 {
		return
	}

	view.Kind = "ufw"
	view.Structured = true
	view.Rules = rules
	view.UFWStatus = status
	view.DefaultPolicy = defaultPolicy
	view.Logging = logging
	view.OpenPorts = openPorts(rules)
	for _, r := range rules {
		switch r.Class {
		case "allow":
			view.AllowCount++
		case "deny", "reject", "limit":
			view.DenyCount++
		default:
			view.OtherCount++
		}
	}
}

func buildNFTablesView(view *FirewallView, c models.Collector) {
	tables := parseNFTRuleset(c.FirewallConfig)
	if len(tables) == 0 {
		return
	}
	for i := range tables {
		tables[i].Flow = nftFlowDiagram(tables[i])
		for _, ch := range tables[i].Chains {
			view.TotalRules += len(ch.Rules)
		}
	}
	view.Kind = "nftables"
	view.Structured = true
	view.NFTables = tables
}

// parseUFWStatusVerbose parses `ufw status verbose` output (what
// firewall.UFW.Status returns, stored verbatim in
// Collector.FirewallConfig) into structured rows. The rule table is
// fixed-width: ufw right-pads "To" and "Action" so every row lines up
// under the header, so column boundaries are read once from the header
// line and every rule sliced at those same offsets — splitting on
// whitespace would break multi-word fields like "Anywhere on
// tailscale0" or "OpenSSH (v6)".
func parseUFWStatusVerbose(raw string, blockedIPs []string) (rules []FirewallRule, status, defaultPolicy, logging string) {
	blocked := make(map[string]bool, len(blockedIPs))
	for _, ip := range blockedIPs {
		blocked[ip] = true
	}

	lines := strings.Split(raw, "\n")
	actionCol, fromCol := -1, -1
	inTable := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "Status:"):
			status = strings.TrimSpace(strings.TrimPrefix(trimmed, "Status:"))
		case strings.HasPrefix(trimmed, "Logging:"):
			logging = strings.TrimSpace(strings.TrimPrefix(trimmed, "Logging:"))
		case strings.HasPrefix(trimmed, "Default:"):
			defaultPolicy = strings.TrimSpace(strings.TrimPrefix(trimmed, "Default:"))
		case !inTable && strings.HasPrefix(trimmed, "To") && strings.Contains(line, "Action") && strings.Contains(line, "From"):
			actionCol = strings.Index(line, "Action")
			fromCol = strings.Index(line, "From")
			inTable = true
			// The next line is the "--  ------  ----" underline — skip
			// it so it doesn't get parsed as a (nonsensical) rule row.
			if i+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "--") {
				i++
			}
		case inTable && trimmed != "":
			rules = append(rules, parseUFWRuleLine(line, actionCol, fromCol, blocked))
		}
	}
	return rules, status, defaultPolicy, logging
}

func parseUFWRuleLine(line string, actionCol, fromCol int, blocked map[string]bool) FirewallRule {
	to := strings.TrimSpace(safeSlice(line, 0, actionCol))
	action := strings.TrimSpace(safeSlice(line, actionCol, fromCol))
	from := strings.TrimSpace(safeSlice(line, fromCol, len(line)))

	class := "other"
	switch {
	case strings.HasPrefix(action, "ALLOW"):
		class = "allow"
	case strings.HasPrefix(action, "DENY"):
		class = "deny"
	case strings.HasPrefix(action, "REJECT"):
		class = "reject"
	case strings.HasPrefix(action, "LIMIT"):
		class = "limit"
	}

	return FirewallRule{
		To:      to,
		Action:  action,
		From:    from,
		Class:   class,
		IPv6:    strings.Contains(to, "(v6)") || strings.Contains(from, "(v6)"),
		OwnRule: blocked[from],
	}
}

// safeSlice is strings slicing that clamps instead of panicking — a
// rule line can be shorter than the header it's supposedly aligned
// under (e.g. a blank "From" column), and this is display code, not
// something that should ever 500 a page over a ragged line.
func safeSlice(s string, start, end int) string {
	if start < 0 || start > len(s) {
		start = len(s)
	}
	if end < 0 || end > len(s) {
		end = len(s)
	}
	if end < start {
		return ""
	}
	return s[start:end]
}

// openPorts returns the distinct "To" values from allow rules that
// name an actual port or service ("22/tcp", "OpenSSH") rather than
// "Anywhere" (what breach-harbor's own address-scoped deny rules use),
// de-duplicating the "(v6)" twin every dual-stack rule produces.
func openPorts(rules []FirewallRule) []string {
	seen := map[string]bool{}
	var ports []string
	for _, r := range rules {
		if r.Class != "allow" {
			continue
		}
		p := strings.TrimSpace(strings.TrimSuffix(r.To, "(v6)"))
		if p == "" || strings.HasPrefix(p, "Anywhere") {
			continue
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	sort.Strings(ports)
	return ports
}
