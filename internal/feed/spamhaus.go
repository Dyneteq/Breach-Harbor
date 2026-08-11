package feed

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"strings"
)

const spamhausDropURL = "https://www.spamhaus.org/drop/drop.txt"

// Spamhaus fetches the Spamhaus DROP (Don't Route Or Peer) list — a
// small, high-confidence list of hijacked/spammer netblocks. No API
// key required.
type Spamhaus struct {
	// URL overrides the real endpoint; tests point this at an
	// httptest.Server. Empty uses spamhausDropURL.
	URL string
}

func NewSpamhaus() *Spamhaus { return &Spamhaus{} }

func (p *Spamhaus) Name() string { return "spamhaus" }

func (p *Spamhaus) RequiresKey() (needed, configured bool) { return false, true }

func (p *Spamhaus) Fetch(ctx context.Context) ([]Entry, error) {
	url := p.URL
	if url == "" {
		url = spamhausDropURL
	}
	data, err := fetchURL(ctx, url, defaultFetchTimeout)
	if err != nil {
		return nil, fmt.Errorf("spamhaus: %w", err)
	}
	return parseSpamhausDrop(data), nil
}

// parseSpamhausDrop parses drop.txt's format — comment lines start
// with ';', data lines are "CIDR ; SBLnnnnn" (the reference/comment
// after ';' is ignored, only the CIDR matters).
func parseSpamhausDrop(data []byte) []Entry {
	var entries []Entry
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		field := strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
		prefix, err := netip.ParsePrefix(field)
		if err != nil {
			continue
		}
		entries = append(entries, Entry{Prefix: prefix, Reason: "spamhaus DROP", Provider: "spamhaus"})
	}
	return entries
}
