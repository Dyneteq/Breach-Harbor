package handlers

import (
	"bufio"
	"regexp"
	"strconv"
	"strings"
)

// nftOwnTable is the nftables table name internal/firewall/nft.go
// creates for breach-harbor's own blocklist (that package's nftTable
// constant) — duplicated here rather than imported since
// internal/handlers has no other reason to depend on internal/
// firewall's exec-shelling code, only its output shape.
const nftOwnTable = "breachharbor"

// NFTable is one `table <family> <name> { ... }` block from an `nft
// list ruleset` dump, parsed for the collector firewall page's
// structured view.
type NFTable struct {
	Family string
	Name   string
	// Warning is the "# Warning: table X is managed by iptables-nft,
	// do not touch!" comment nft prints directly above a table it
	// knows some other tool (ufw, iptables-nft itself) owns, if any.
	Warning string
	// IsOwn marks breach-harbor's own table, so the template can
	// visually distinguish it from every other tool's tables sharing
	// the same nftables ruleset.
	IsOwn  bool
	Chains []NFChain
	Sets   []NFSet
}

// NFChain is one `chain <name> { ... }` block within a table.
type NFChain struct {
	Name string
	// Header is the base-chain declaration line ("type filter hook
	// input priority filter; policy drop;"), empty for a non-base
	// (regular/jump-target) chain.
	Header string
	// HeaderShort is Header condensed to "hook input, policy drop" for
	// a one-line chain label — falls back to Header verbatim if it
	// doesn't match the expected shape.
	HeaderShort string
	Rules       []NFRule
}

// NFRule is one rule line within a chain, split into its displayable
// parts: the match condition, the terminal verdict, and (if present)
// the packet/byte counter nft prints inline.
type NFRule struct {
	Raw   string
	Match string
	// Verdict is the rule's terminal statement — "accept", "drop",
	// "jump <chain>", "reject ...", "log ...", or "" if none was
	// recognized (rare; usually means the rule is just a counter/log
	// with no explicit verdict, falling through to the chain policy).
	Verdict string
	// VerdictClass is a Bootstrap color suffix ("success", "danger",
	// ...) precomputed at parse time so the template needs no custom
	// FuncMap entry to color the badge.
	VerdictClass string
	Packets      uint64
	Bytes        uint64
	HasCounter   bool
	// PacketsHuman is Packets formatted compactly ("1.2K", "3.4M") for
	// the condensed rule row — precomputed so the template needs no
	// custom FuncMap entry.
	PacketsHuman string
}

// NFSet is one `set <name> { ... }` block within a table — breach-
// harbor's own blocked4/blocked6 sets, fail2ban's banned-address set,
// or any other tool's.
type NFSet struct {
	Name     string
	TypeLine string
	Elements []string
}

var (
	nftTableOpenRe = regexp.MustCompile(`^table\s+(\S+)\s+(\S+)\s*\{$`)
	nftChainOpenRe = regexp.MustCompile(`^chain\s+(\S+)\s*\{$`)
	nftSetOpenRe   = regexp.MustCompile(`^set\s+(\S+)\s*\{$`)
	nftCounterRe   = regexp.MustCompile(`counter packets (\d+) bytes (\d+)`)
	nftSpacesRe    = regexp.MustCompile(`\s+`)
	nftHeaderRe    = regexp.MustCompile(`hook\s+(\S+)\s+priority\s+([^;]+);\s*policy\s+(\S+?);?\s*$`)
)

// parseNFTRuleset parses `nft list ruleset` output (what
// firewall.NFTables.Status returns, stored verbatim in
// Collector.FirewallConfig) into a browsable table/chain/rule/set
// tree. This is a pragmatic line-and-brace tracker, not a real nft
// grammar — it's built against nft's own pretty-printer output shape
// (consistent one-block-per-line, 1-2 levels of nesting), not against
// hand-written or minified rulesets, which is exactly what a Status()
// dump always is.
func parseNFTRuleset(raw string) []NFTable {
	var tables []NFTable
	var cur *NFTable
	var curChain *NFChain
	var curSet *NFSet
	var pendingWarning string
	var elemBuf strings.Builder
	collectingElems := false

	flushChain := func() {
		if curChain != nil && cur != nil {
			cur.Chains = append(cur.Chains, *curChain)
		}
		curChain = nil
	}
	flushSet := func() {
		if curSet != nil && cur != nil {
			cur.Sets = append(cur.Sets, *curSet)
		}
		curSet = nil
	}
	flushTable := func() {
		flushChain()
		flushSet()
		if cur != nil {
			tables = append(tables, *cur)
		}
		cur = nil
	}
	parseElements := func(full string) []string {
		start := strings.Index(full, "{")
		end := strings.LastIndex(full, "}")
		if start == -1 || end == -1 || end <= start {
			return nil
		}
		var elems []string
		for _, e := range strings.Split(full[start+1:end], ",") {
			e = strings.TrimSpace(e)
			if e != "" {
				elems = append(elems, e)
			}
		}
		return elems
	}

	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Strip a trailing inline comment (nft sometimes appends one
		// to flag a rule it couldn't fully translate, e.g. an
		// untranslatable legacy xtables target) — never strip a
		// whole-line comment, that's handled below.
		if idx := strings.Index(line, " #"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// A long `elements = { ... }` list wraps across several lines
		// once a set has more than a handful of entries — this takes
		// priority over every other case while a wrapped list is in
		// progress, mirroring internal/firewall/nft.go's own
		// parseNFTSetElements fix.
		if collectingElems {
			elemBuf.WriteString(" ")
			elemBuf.WriteString(line)
			if strings.Contains(line, "}") {
				collectingElems = false
				if curSet != nil {
					curSet.Elements = append(curSet.Elements, parseElements(elemBuf.String())...)
				}
				elemBuf.Reset()
			}
			continue
		}

		switch {
		case strings.HasPrefix(line, "#"):
			if cur == nil {
				pendingWarning = strings.TrimSpace(strings.TrimPrefix(line, "#"))
			}
		case cur == nil:
			if m := nftTableOpenRe.FindStringSubmatch(line); m != nil {
				cur = &NFTable{Family: m[1], Name: m[2], Warning: pendingWarning, IsOwn: m[2] == nftOwnTable}
				pendingWarning = ""
			}
		case curChain != nil:
			switch {
			case line == "}":
				flushChain()
			case curChain.Header == "" && strings.HasPrefix(line, "type ") && strings.Contains(line, "hook"):
				curChain.Header = line
				curChain.HeaderShort = shortenNFTHeader(line)
			default:
				curChain.Rules = append(curChain.Rules, parseNFTRule(line))
			}
		case curSet != nil:
			switch {
			case line == "}":
				flushSet()
			case strings.HasPrefix(line, "elements"):
				if strings.Contains(line, "}") {
					curSet.Elements = append(curSet.Elements, parseElements(line)...)
				} else {
					collectingElems = true
					elemBuf.Reset()
					elemBuf.WriteString(line)
				}
			case curSet.TypeLine == "":
				curSet.TypeLine = line
			}
		default: // inside a table, not currently inside a chain or set
			switch {
			case line == "}":
				flushTable()
			default:
				if m := nftChainOpenRe.FindStringSubmatch(line); m != nil {
					curChain = &NFChain{Name: m[1]}
				} else if m := nftSetOpenRe.FindStringSubmatch(line); m != nil {
					curSet = &NFSet{Name: m[1]}
				}
				// Anything else at table level (a map, a flowtable —
				// none of which breach-harbor or the tools it shares
				// a host with produce) is silently skipped rather
				// than misrendered.
			}
		}
	}
	return tables
}

// parseNFTRule splits one rule line into its match condition, verdict,
// and counter, so the template can show a colored verdict badge and
// numeric counters instead of one long opaque line.
func parseNFTRule(raw string) NFRule {
	r := NFRule{Raw: raw}
	text := raw

	if m := nftCounterRe.FindStringSubmatch(text); m != nil {
		if p, err := strconv.ParseUint(m[1], 10, 64); err == nil {
			r.Packets = p
			r.HasCounter = true
		}
		if b, err := strconv.ParseUint(m[2], 10, 64); err == nil {
			r.Bytes = b
		}
		text = strings.TrimSpace(nftCounterRe.ReplaceAllString(text, ""))
		text = strings.TrimSpace(nftSpacesRe.ReplaceAllString(text, " "))
		r.PacketsHuman = humanizeCount(r.Packets)
	}

	match, verdict := extractNFTVerdict(text)
	r.Match = strings.TrimSpace(match)
	r.Verdict = verdict
	r.VerdictClass = nftVerdictClass(verdict)
	return r
}

// shortenNFTHeader condenses a base-chain declaration line ("type
// filter hook input priority filter; policy drop;") into a one-line
// label ("hook input, policy drop") for the condensed chain header —
// falls back to the line verbatim if it doesn't match the expected
// shape (unusual chain types this parser hasn't seen).
func shortenNFTHeader(line string) string {
	m := nftHeaderRe.FindStringSubmatch(line)
	if m == nil {
		return line
	}
	return "hook " + m[1] + ", policy " + m[3]
}

// humanizeCount compactly formats a packet/byte counter ("1.2K",
// "3.4M") so a rule row's counter column stays a fixed, scannable
// width instead of a long raw integer.
func humanizeCount(n uint64) string {
	var val float64
	var suffix string
	switch {
	case n >= 1_000_000_000:
		val, suffix = float64(n)/1_000_000_000, "G"
	case n >= 1_000_000:
		val, suffix = float64(n)/1_000_000, "M"
	case n >= 1_000:
		val, suffix = float64(n)/1_000, "K"
	default:
		return strconv.FormatUint(n, 10)
	}
	s := strconv.FormatFloat(val, 'f', 1, 64)
	s = strings.TrimSuffix(s, ".0")
	return s + suffix
}

// extractNFTVerdict pulls the terminal statement off the end of a
// (counter-stripped) rule line. nft rule syntax always ends in exactly
// one terminal statement, so this only ever looks at the tail — never
// the match conditions earlier in the line, which could otherwise
// contain the same keywords (e.g. a match on a "drop" comment string).
func extractNFTVerdict(text string) (rest, verdict string) {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return text, ""
	}
	last := fields[len(fields)-1]
	switch last {
	case "accept", "drop", "continue", "return", "queue":
		return strings.TrimSuffix(text, last), last
	}
	if len(fields) >= 2 {
		if verb := fields[len(fields)-2]; verb == "jump" || verb == "goto" {
			v := verb + " " + last
			return strings.TrimSuffix(text, v), v
		}
	}
	if idx := strings.Index(text, "reject"); idx != -1 {
		return text[:idx], strings.TrimSpace(text[idx:])
	}
	if idx := strings.Index(text, "masquerade"); idx != -1 {
		return text[:idx], "masquerade"
	}
	if idx := strings.Index(text, "log prefix"); idx != -1 {
		return text[:idx], strings.TrimSpace(text[idx:])
	}
	return text, ""
}

// nftVerdictClass maps a parsed verdict to a Bootstrap badge color.
func nftVerdictClass(verdict string) string {
	switch {
	case verdict == "":
		return ""
	case verdict == "accept":
		return "success"
	case verdict == "drop", strings.HasPrefix(verdict, "reject"):
		return "danger"
	case strings.HasPrefix(verdict, "jump"), strings.HasPrefix(verdict, "goto"):
		return "secondary"
	case verdict == "masquerade", strings.HasPrefix(verdict, "snat"), strings.HasPrefix(verdict, "dnat"):
		return "info"
	case strings.HasPrefix(verdict, "log"):
		return "light"
	default:
		return "secondary"
	}
}
