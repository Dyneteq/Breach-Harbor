package handlers

import (
	"strconv"
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

func TestExplainNFTRule(t *testing.T) {
	cases := []struct {
		match, verdict string
		want           string
	}{
		{`iifname "lo"`, "accept", "Loopback (localhost) traffic"},
		{"ct state related,established", "accept", "Return traffic for connections already allowed out"},
		{"ct state invalid", "drop", "Malformed or untracked packet"},
		{"ip protocol icmp icmp type echo-request", "accept", "Ping (ICMP echo)"},
		{"ip protocol icmp icmp type destination-unreachable", "accept", "ICMP diagnostic message"},
		{"meta l4proto ipv6-icmp icmpv6 type nd-router-solicit ip6 hoplimit 255", "accept", "IPv6 neighbor discovery"},
		{"fib daddr type local", "return", "Destined for this host"},
		{"fib daddr type broadcast", "return", "Broadcast destination"},
		{"tcp dport 22", "accept", "Port 22 (SSH)"},
		{"udp dport 41641", "accept", "Port 41641 (Tailscale)"},
		{"tcp dport 9999", "accept", "Port 9999"},
		{`iifname "tailscale0"`, "accept", "Incoming on interface tailscale0"},
		{`oifname "tailscale0"`, "accept", "Outgoing on interface tailscale0"},
		{"ip saddr 100.64.0.0/10", "drop", "Traffic from 100.64.0.0/10"},
		{"ip6 daddr ff02::fb", "accept", "Traffic to ff02::fb"},
		{"limit rate 3/minute burst 10 packets", "return", "Rate-limited"},
		{"", "masquerade", "Rewrites the packet's address (NAT)"},
		{"meta mark & 0x00ff0000 == 0x00040000", "masquerade", "Rewrites the packet's address (NAT)"},
		{"some completely novel expression nft has never produced", "accept", ""},
		{"", "accept", ""},
	}
	for _, c := range cases {
		if got := explainNFTRule(c.match, c.verdict); got != c.want {
			t.Errorf("explainNFTRule(%q, %q) = %q, want %q", c.match, c.verdict, got, c.want)
		}
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

func TestNFTFlowDiagram_TracesReachableJumpChain(t *testing.T) {
	tables := parseNFTRuleset(sampleNFTRuleset)
	ipFilter := tables[0]
	flow := nftFlowDiagram(ipFilter)
	if flow == "" {
		t.Fatal("expected a non-empty flow diagram for ip filter")
	}
	if !strings.HasPrefix(flow, "flowchart LR\n") {
		t.Errorf("flow = %q, want it to start with a Mermaid flowchart header", flow)
	}

	// INPUT -> ufw-before-input -> ufw-user-input is the only path
	// that's actually reachable within this table's declared chains
	// (INPUT also jumps to "ts-input" and ufw-before-input jumps to
	// "ufw-logging-deny", neither of which this trimmed fixture
	// declares — those edges must be silently dropped, not crash or
	// reference an undefined node).
	for _, id := range []string{nftNodeID("INPUT"), nftNodeID("ufw-before-input"), nftNodeID("ufw-user-input")} {
		if !strings.Contains(flow, id) {
			t.Errorf("expected node id %q in flow, got:\n%s", id, flow)
		}
	}
	for _, name := range []string{"ts-input", "ufw-logging-deny"} {
		if strings.Contains(flow, nftNodeID(name)) {
			t.Errorf("expected no reference to undeclared chain %q, got:\n%s", name, flow)
		}
	}

	// Chains that are neither a base chain nor reachable via any edge
	// (ufw-before-logging-input has 0 rules and nothing jumps to it in
	// this fixture; ufw-skip-to-policy-input is never jumped to
	// either) must be excluded as clutter.
	for _, name := range []string{"ufw-before-logging-input", "ufw-skip-to-policy-input"} {
		if strings.Contains(flow, nftNodeID(name)) {
			t.Errorf("expected unreferenced chain %q to be excluded, got:\n%s", name, flow)
		}
	}
}

func TestNFTFlowDiagram_BaseChainGetsClassed(t *testing.T) {
	tables := parseNFTRuleset(sampleNFTRuleset)
	flow := nftFlowDiagram(tables[0])
	if !strings.Contains(flow, "class "+nftNodeID("INPUT")+" nftBaseChain") {
		t.Errorf("expected INPUT to be classed as a base chain, got:\n%s", flow)
	}
	if strings.Contains(flow, "class "+nftNodeID("ufw-user-input")+" nftBaseChain") {
		t.Error("expected ufw-user-input (not a base chain) to not get the base-chain class")
	}
}

func TestNFTFlowDiagram_SingleBaseChainNoJumps(t *testing.T) {
	tables := parseNFTRuleset(sampleNFTRuleset)
	var f2b *NFTable
	for i := range tables {
		if tables[i].Name == "f2b-table" {
			f2b = &tables[i]
		}
	}
	if f2b == nil {
		t.Fatal("expected f2b-table")
	}
	flow := nftFlowDiagram(*f2b)
	if flow == "" {
		t.Fatal("expected a diagram even with a single, jump-free base chain")
	}
	if !strings.Contains(flow, nftNodeID("f2b-chain")) {
		t.Errorf("expected the f2b-chain node, got:\n%s", flow)
	}
	if strings.Contains(flow, "-->") {
		t.Errorf("expected no edges (nothing jumps anywhere), got:\n%s", flow)
	}
}

func TestNFTFlowDiagram_EmptyWhenNoChains(t *testing.T) {
	tables := parseNFTRuleset(sampleNFTRuleset)
	var own *NFTable
	for i := range tables {
		if tables[i].IsOwn {
			own = &tables[i]
		}
	}
	if own == nil {
		t.Fatal("expected the breachharbor table")
	}
	if got := nftFlowDiagram(*own); got != "" {
		t.Errorf("expected no diagram for a table with 0 chains, got %q", got)
	}
}

func TestNFTJumpTarget(t *testing.T) {
	cases := []struct {
		verdict, wantTarget, wantKind string
	}{
		{"jump ufw-user-input", "ufw-user-input", "jump"},
		{"goto ufw-user-input", "ufw-user-input", "goto"},
		{"accept", "", ""},
		{"drop", "", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		target, kind := nftJumpTarget(c.verdict)
		if target != c.wantTarget || kind != c.wantKind {
			t.Errorf("nftJumpTarget(%q) = (%q, %q), want (%q, %q)", c.verdict, target, kind, c.wantTarget, c.wantKind)
		}
	}
}

func TestNFTNodeID(t *testing.T) {
	cases := []struct{ in, want string }{
		{"ufw-user-input", "ufw_user_input"},
		{"INPUT", "INPUT"},
		{"f2b-chain", "f2b_chain"},
	}
	for _, c := range cases {
		if got := nftNodeID(c.in); got != c.want {
			t.Errorf("nftNodeID(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestNFTFlowNodeLabel_SingleLine guards half of why the flow diagram
// is safe to render even though chain names ultimately come from a
// monitored (and possibly compromised) host's own self-reported nft
// output: labels are always single-line — an embedded newline could
// otherwise let a crafted chain name inject an extra Mermaid
// statement (a rogue edge, a classDef) onto its own line.
func TestNFTFlowNodeLabel_SingleLine(t *testing.T) {
	ch := NFChain{
		Name:        "evil\nclassDef x fill:red",
		HeaderShort: "hook input, policy drop",
		Rules:       []NFRule{{VerdictClass: "success"}, {VerdictClass: "danger"}},
	}
	label := nftFlowNodeLabel(ch)
	if strings.ContainsAny(label, "\n\r") {
		t.Errorf("label must be single-line, got %q", label)
	}
}

// TestNFTFlowDiagram_QuoteEscaping guards the other half: a chain name
// containing a double quote or Mermaid syntax must not be able to
// close the label's quoted string early and inject raw Mermaid
// statements. nftFlowDiagram runs every label through strconv.Quote,
// so this asserts that exact escaped form is what actually lands in
// the diagram text — proving the escaping is applied, not just
// assumed.
func TestNFTFlowDiagram_QuoteEscaping(t *testing.T) {
	evilName := `evil" ]; classDef x fill:red //`
	tbl := NFTable{
		Name: "t",
		Chains: []NFChain{
			{Name: evilName, Header: "type filter hook input priority filter; policy drop;"},
		},
	}
	flow := nftFlowDiagram(tbl)
	if flow == "" {
		t.Fatal("expected a non-empty diagram for a single base chain")
	}
	wantEscaped := strconv.Quote(nftFlowNodeLabel(tbl.Chains[0]))
	if !strings.Contains(flow, wantEscaped) {
		t.Errorf("expected the properly escaped label %s in output, got:\n%s", wantEscaped, flow)
	}
	// The raw, unescaped name must never appear on its own — only
	// inside the escaped/quoted form checked above.
	if strings.Contains(flow, evilName) {
		t.Errorf("raw unescaped chain name leaked into diagram output:\n%s", flow)
	}
}

func TestNFTFlowNodeLabel_TruncatesLongNames(t *testing.T) {
	ch := NFChain{Name: strings.Repeat("x", 200)}
	label := nftFlowNodeLabel(ch)
	// Bounded by rune (display) count, not byte length — the ellipsis
	// itself is a 3-byte UTF-8 rune, so a byte-length check would
	// under-count how much of the label it can actually keep.
	if n := len([]rune(label)); n > nftFlowLabelMaxLen {
		t.Errorf("label rune length = %d, want <= %d", n, nftFlowLabelMaxLen)
	}
	if !strings.HasSuffix(label, "…") {
		t.Errorf("expected a truncated label to end with an ellipsis, got %q", label)
	}
}
