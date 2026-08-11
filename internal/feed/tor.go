package feed

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"strings"
)

const torExitListURL = "https://check.torproject.org/torbulkexitlist"

// Tor fetches the current list of Tor exit node IPs. No API key
// required. Each entry is an exact IP (a /32 or /128 prefix), not a
// range — a Tor exit is either that address or it isn't.
type Tor struct {
	// URL overrides the real endpoint; tests point this at an
	// httptest.Server. Empty uses torExitListURL.
	URL string
}

func NewTor() *Tor { return &Tor{} }

func (p *Tor) Name() string { return "tor" }

func (p *Tor) RequiresKey() (needed, configured bool) { return false, true }

func (p *Tor) Fetch(ctx context.Context) ([]Entry, error) {
	url := p.URL
	if url == "" {
		url = torExitListURL
	}
	data, err := fetchURL(ctx, url, defaultFetchTimeout)
	if err != nil {
		return nil, fmt.Errorf("tor: %w", err)
	}
	return parseTorExitList(data), nil
}

func parseTorExitList(data []byte) []Entry {
	var entries []Entry
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		addr, err := netip.ParseAddr(line)
		if err != nil {
			continue
		}
		entries = append(entries, Entry{Prefix: netip.PrefixFrom(addr, addr.BitLen()), Reason: "tor exit node", Provider: "tor"})
	}
	return entries
}
