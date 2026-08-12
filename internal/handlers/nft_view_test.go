package handlers

import (
	"strings"
	"testing"

	"github.com/Dyneteq/Breach-Harbor/internal/models"
)

// sampleNFTRuleset is a trimmed but structurally faithful excerpt of a
// real `nft list ruleset` dump from a host running ufw (backed by
// iptables-nft), fail2ban, tailscale, and breach-harbor's own nftables
// backend side by side — the exact multi-tool situation that motivated
// a real, structured parser instead of a flat text dump.
const sampleNFTRuleset = `# Warning: table ip filter is managed by iptables-nft, do not touch!
table ip filter {
	chain ufw-before-logging-input {
	}

	chain ufw-before-input {
		iifname "lo" counter packets 880 bytes 91243 accept
		ct state invalid counter packets 192 bytes 62175 jump ufw-logging-deny
		counter packets 22468 bytes 1381225 jump ufw-user-input
	}

	chain INPUT {
		type filter hook input priority filter; policy drop;
		counter packets 81985 bytes 51534121 jump ts-input
		counter packets 55521 bytes 36319870 jump ufw-before-input
	}

	chain ufw-user-input {
		tcp dport 22  counter packets 1142 bytes 69268 accept
		tcp dport 80 counter packets 882 bytes 50513 accept
		iifname "tailscale0" counter packets 0 bytes 0 accept
	}

	chain ufw-skip-to-policy-input {
		counter packets 135 bytes 6990 drop
	}
}
table inet f2b-table {
	set addr-set-sshd {
		type ipv4_addr
		elements = { 45.148.10.141, 45.148.10.152,
			     45.148.10.157, 91.92.40.239 }
	}

	chain f2b-chain {
		type filter hook input priority filter - 1; policy accept;
		tcp dport 22 ip saddr @addr-set-sshd reject with icmp port-unreachable
	}
}
table inet breachharbor {
	set blocked4 {
		type ipv4_addr
		flags interval
		elements = { 39.171.240.69, 45.148.10.141,
			     45.148.10.147, 45.148.10.151,
			     45.148.10.152 }
	}

	set blocked6 {
		type ipv6_addr
		flags interval
	}
}
`

func TestParseNFTRuleset_TableCount(t *testing.T) {
	tables := parseNFTRuleset(sampleNFTRuleset)
	if len(tables) != 3 {
		t.Fatalf("got %d tables, want 3: %+v", len(tables), tables)
	}
}

func TestParseNFTRuleset_WarningAttachedToRightTable(t *testing.T) {
	tables := parseNFTRuleset(sampleNFTRuleset)
	if tables[0].Family != "ip" || tables[0].Name != "filter" {
		t.Fatalf("tables[0] = %+v, want ip filter", tables[0])
	}
	if !strings.Contains(tables[0].Warning, "managed by iptables-nft") {
		t.Errorf("tables[0].Warning = %q, want it to mention iptables-nft", tables[0].Warning)
	}
	if tables[1].Warning != "" {
		t.Errorf("tables[1].Warning = %q, want empty (no comment preceded it)", tables[1].Warning)
	}
}

func TestParseNFTRuleset_OwnTableFlagged(t *testing.T) {
	tables := parseNFTRuleset(sampleNFTRuleset)
	for _, tbl := range tables {
		want := tbl.Name == "breachharbor"
		if tbl.IsOwn != want {
			t.Errorf("table %s: IsOwn = %v, want %v", tbl.Name, tbl.IsOwn, want)
		}
	}
}

func TestParseNFTRuleset_EmptyChainsSkippedFromCounts(t *testing.T) {
	tables := parseNFTRuleset(sampleNFTRuleset)
	ipFilter := tables[0]
	var found bool
	for _, ch := range ipFilter.Chains {
		if ch.Name == "ufw-before-logging-input" {
			found = true
			if len(ch.Rules) != 0 {
				t.Errorf("expected ufw-before-logging-input to have 0 rules, got %d", len(ch.Rules))
			}
		}
	}
	if !found {
		t.Fatal("expected the empty chain to still be parsed (just with 0 rules), not dropped entirely")
	}
}

func TestParseNFTRuleset_ChainHeaderCapturedSeparatelyFromRules(t *testing.T) {
	tables := parseNFTRuleset(sampleNFTRuleset)
	var input *NFChain
	for i := range tables[0].Chains {
		if tables[0].Chains[i].Name == "INPUT" {
			input = &tables[0].Chains[i]
		}
	}
	if input == nil {
		t.Fatal("expected an INPUT chain in the ip filter table")
	}
	if !strings.Contains(input.Header, "policy drop") {
		t.Errorf("Header = %q, want it to contain the base-chain declaration", input.Header)
	}
	if input.HeaderShort != "hook input, policy drop" {
		t.Errorf("HeaderShort = %q, want %q", input.HeaderShort, "hook input, policy drop")
	}
	if len(input.Rules) != 2 {
		t.Fatalf("got %d rules, want 2 (the header line must not be counted as a rule): %+v", len(input.Rules), input.Rules)
	}
}

func TestShortenNFTHeader(t *testing.T) {
	cases := []struct{ in, want string }{
		{"type filter hook input priority filter; policy drop;", "hook input, policy drop"},
		{"type filter hook input priority filter - 1; policy accept;", "hook input, policy accept"},
		{"type nat hook postrouting priority srcnat; policy accept;", "hook postrouting, policy accept"},
		{"something nft has never produced before", "something nft has never produced before"},
	}
	for _, c := range cases {
		if got := shortenNFTHeader(c.in); got != c.want {
			t.Errorf("shortenNFTHeader(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHumanizeCount(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "0"},
		{42, "42"},
		{999, "999"},
		{1000, "1K"},
		{1500, "1.5K"},
		{177992, "178K"},
		{1_000_000, "1M"},
		{1_234_567, "1.2M"},
		{1_000_000_000, "1G"},
	}
	for _, c := range cases {
		if got := humanizeCount(c.in); got != c.want {
			t.Errorf("humanizeCount(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseNFTRuleset_VerdictsAndCounters(t *testing.T) {
	tables := parseNFTRuleset(sampleNFTRuleset)
	var userInput *NFChain
	for i := range tables[0].Chains {
		if tables[0].Chains[i].Name == "ufw-user-input" {
			userInput = &tables[0].Chains[i]
		}
	}
	if userInput == nil {
		t.Fatal("expected ufw-user-input chain")
	}
	if len(userInput.Rules) != 3 {
		t.Fatalf("got %d rules, want 3: %+v", len(userInput.Rules), userInput.Rules)
	}
	r := userInput.Rules[0]
	if r.Verdict != "accept" {
		t.Errorf("Verdict = %q, want accept", r.Verdict)
	}
	if r.VerdictClass != "success" {
		t.Errorf("VerdictClass = %q, want success", r.VerdictClass)
	}
	if !r.HasCounter || r.Packets != 1142 || r.Bytes != 69268 {
		t.Errorf("counter = (has=%v packets=%d bytes=%d), want (true 1142 69268)", r.HasCounter, r.Packets, r.Bytes)
	}
	if !strings.Contains(r.Match, "tcp dport 22") {
		t.Errorf("Match = %q, want it to contain the match condition with the verdict/counter stripped out", r.Match)
	}
	if strings.Contains(r.Match, "accept") || strings.Contains(r.Match, "counter") {
		t.Errorf("Match = %q, must not still contain the verdict or counter text", r.Match)
	}
}

func TestParseNFTRuleset_JumpVerdict(t *testing.T) {
	tables := parseNFTRuleset(sampleNFTRuleset)
	var beforeInput *NFChain
	for i := range tables[0].Chains {
		if tables[0].Chains[i].Name == "ufw-before-input" {
			beforeInput = &tables[0].Chains[i]
		}
	}
	if beforeInput == nil {
		t.Fatal("expected ufw-before-input chain")
	}
	last := beforeInput.Rules[len(beforeInput.Rules)-1]
	if last.Verdict != "jump ufw-user-input" {
		t.Errorf("Verdict = %q, want %q", last.Verdict, "jump ufw-user-input")
	}
	if last.VerdictClass != "secondary" {
		t.Errorf("VerdictClass = %q, want secondary", last.VerdictClass)
	}
}

func TestParseNFTRuleset_DropVerdict(t *testing.T) {
	tables := parseNFTRuleset(sampleNFTRuleset)
	var skip *NFChain
	for i := range tables[0].Chains {
		if tables[0].Chains[i].Name == "ufw-skip-to-policy-input" {
			skip = &tables[0].Chains[i]
		}
	}
	if skip == nil || len(skip.Rules) != 1 {
		t.Fatalf("expected exactly 1 rule in ufw-skip-to-policy-input, got %+v", skip)
	}
	if skip.Rules[0].Verdict != "drop" || skip.Rules[0].VerdictClass != "danger" {
		t.Errorf("got Verdict=%q Class=%q, want drop/danger", skip.Rules[0].Verdict, skip.Rules[0].VerdictClass)
	}
}

func TestParseNFTRuleset_RejectWithDetailVerdict(t *testing.T) {
	tables := parseNFTRuleset(sampleNFTRuleset)
	f2b := tables[1]
	if f2b.Name != "f2b-table" {
		t.Fatalf("tables[1] = %+v, want f2b-table", f2b)
	}
	if len(f2b.Chains) != 1 || len(f2b.Chains[0].Rules) != 1 {
		t.Fatalf("expected exactly 1 chain with 1 rule in f2b-table, got %+v", f2b.Chains)
	}
	r := f2b.Chains[0].Rules[0]
	if !strings.HasPrefix(r.Verdict, "reject") {
		t.Errorf("Verdict = %q, want it to start with reject", r.Verdict)
	}
	if r.VerdictClass != "danger" {
		t.Errorf("VerdictClass = %q, want danger", r.VerdictClass)
	}
}

func TestParseNFTRuleset_SetsParsedIncludingWrappedElements(t *testing.T) {
	tables := parseNFTRuleset(sampleNFTRuleset)
	f2b := tables[1]
	if len(f2b.Sets) != 1 || f2b.Sets[0].Name != "addr-set-sshd" {
		t.Fatalf("expected addr-set-sshd set in f2b-table, got %+v", f2b.Sets)
	}
	if len(f2b.Sets[0].Elements) != 4 {
		t.Errorf("got %d elements, want 4 (wrapped across two lines): %+v", len(f2b.Sets[0].Elements), f2b.Sets[0].Elements)
	}

	own := tables[2]
	var blocked4, blocked6 *NFSet
	for i := range own.Sets {
		switch own.Sets[i].Name {
		case "blocked4":
			blocked4 = &own.Sets[i]
		case "blocked6":
			blocked6 = &own.Sets[i]
		}
	}
	if blocked4 == nil || len(blocked4.Elements) != 5 {
		t.Fatalf("blocked4 = %+v, want 5 elements", blocked4)
	}
	if blocked6 == nil || len(blocked6.Elements) != 0 {
		t.Fatalf("blocked6 = %+v, want 0 elements (declared with no elements line)", blocked6)
	}
}

func TestBuildFirewallView_NFTables_Structured(t *testing.T) {
	c := models.Collector{
		Name:               "hetzner-1",
		FirewallBackend:    "nftables",
		FirewallEnforcing:  true,
		FirewallBlockedIPs: []string{"39.171.240.69", "45.148.10.141", "45.148.10.147", "45.148.10.151", "45.148.10.152"},
		FirewallConfig:     sampleNFTRuleset,
	}
	view := BuildFirewallView(c)
	if view.Kind != "nftables" {
		t.Fatalf("Kind = %q, want nftables", view.Kind)
	}
	if !view.Structured {
		t.Error("expected Structured to be true")
	}
	if len(view.NFTables) != 3 {
		t.Errorf("got %d tables, want 3", len(view.NFTables))
	}
	if view.TotalRules == 0 {
		t.Error("expected TotalRules to be nonzero")
	}
}
