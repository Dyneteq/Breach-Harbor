package feed

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"strings"
)

const fireholLevel1URL = "https://iplists.firehol.org/files/firehol_level1.netset"

// Firehol fetches FireHOL's level1 netset — a broad, low-false-positive
// aggregate blocklist (Spamhaus DROP/EDROP, DShield, and others,
// deduplicated). No API key required.
type Firehol struct {
	// URL overrides the real endpoint; tests point this at an
	// httptest.Server. Empty uses fireholLevel1URL.
	URL string
}

func NewFirehol() *Firehol { return &Firehol{} }

func (p *Firehol) Name() string { return "firehol" }

func (p *Firehol) RequiresKey() (needed, configured bool) { return false, true }

func (p *Firehol) Fetch(ctx context.Context) ([]Entry, error) {
	url := p.URL
	if url == "" {
		url = fireholLevel1URL
	}
	data, err := fetchURL(ctx, url, defaultFetchTimeout)
	if err != nil {
		return nil, fmt.Errorf("firehol: %w", err)
	}
	return parseFireholNetset(data), nil
}

// parseFireholNetset parses a .netset file — comments start with '#',
// data lines are bare CIDRs (or occasionally a bare IP, treated as a
// /32 or /128).
func parseFireholNetset(data []byte) []Entry {
	var entries []Entry
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			addr, aerr := netip.ParseAddr(line)
			if aerr != nil {
				continue
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		entries = append(entries, Entry{Prefix: prefix, Reason: "firehol level1", Provider: "firehol"})
	}
	return entries
}
