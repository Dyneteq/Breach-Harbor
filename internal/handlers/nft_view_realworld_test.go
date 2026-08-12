package handlers

import (
	"os"
	"testing"

	"github.com/Dyneteq/Breach-Harbor/internal/models"
)

// TestParseNFTRuleset_RealWorldDump replays an actual `nft list
// ruleset` dump collected from a production host running ufw (backed
// by iptables-nft), fail2ban, and tailscale alongside breach-harbor's
// own nftables backend — the shape that first exposed the "Blocked by
// breach-harbor: 0" bug (parseNFTSetElements only reading a same-line
// "elements = { ... }", which silently drops every set nft wraps
// across multiple lines, exactly what happens once a blocklist has
// more than a handful of entries). Every address here is either a
// public threat-intel blocklist entry breach-harbor added or an
// RFC 4193 tailscale ULA — nothing private.
func TestParseNFTRuleset_RealWorldDump(t *testing.T) {
	data, err := os.ReadFile("testdata/full_dump.txt")
	if err != nil {
		t.Fatal(err)
	}
	c := models.Collector{
		Name:               "hetzner-1",
		FirewallBackend:    "nftables",
		FirewallEnforcing:  true,
		FirewallBlockedIPs: nil,
		FirewallConfig:     string(data),
	}
	view := BuildFirewallView(c)
	t.Logf("Kind=%s Structured=%v TotalRules=%d Tables=%d", view.Kind, view.Structured, view.TotalRules, len(view.NFTables))
	if !view.Structured || view.Kind != "nftables" {
		t.Fatalf("expected a structured nftables view, got Kind=%q Structured=%v", view.Kind, view.Structured)
	}
	if len(view.NFTables) != 8 {
		t.Errorf("got %d tables, want 8 (ip filter, ip6 filter, inet f2b-table, ip nat, ip6 nat, ip mangle, ip6 mangle, inet breachharbor)", len(view.NFTables))
	}
	var own *NFTable
	for i := range view.NFTables {
		tbl := &view.NFTables[i]
		t.Logf("table %s %s own=%v warning=%q chains=%d sets=%d", tbl.Family, tbl.Name, tbl.IsOwn, tbl.Warning, len(tbl.Chains), len(tbl.Sets))
		if tbl.IsOwn {
			own = tbl
		}
		for _, ch := range tbl.Chains {
			for _, r := range ch.Rules {
				if r.Verdict == "" && r.Match == "" {
					t.Errorf("table %s chain %s: empty rule parsed from raw %q", tbl.Name, ch.Name, r.Raw)
				}
			}
		}
	}
	if own == nil {
		t.Fatal("expected the breachharbor table to be found and flagged IsOwn")
	}
	for _, s := range own.Sets {
		t.Logf("  own set %s elements=%d", s.Name, len(s.Elements))
		if s.Name == "blocked4" && len(s.Elements) != 23 {
			t.Errorf("blocked4 elements = %d, want 23", len(s.Elements))
		}
	}
}
