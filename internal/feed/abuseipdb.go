package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
)

const abuseIPDBBlacklistURL = "https://api.abuseipdb.com/api/v2/blacklist"

// AbuseIPDB fetches AbuseIPDB's blacklist endpoint. Unlike the other
// providers this needs an API key (--abuseipdb-key) — without one,
// Fetch returns an empty result rather than an error, since "the user
// didn't opt in" is not a failure.
type AbuseIPDB struct {
	// URL overrides the real endpoint; tests point this at an
	// httptest.Server. Empty uses abuseIPDBBlacklistURL.
	URL    string
	APIKey string
}

func NewAbuseIPDB(apiKey string) *AbuseIPDB { return &AbuseIPDB{APIKey: apiKey} }

func (p *AbuseIPDB) Name() string { return "abuseipdb" }

func (p *AbuseIPDB) RequiresKey() (needed, configured bool) { return true, p.APIKey != "" }

func (p *AbuseIPDB) Fetch(ctx context.Context) ([]Entry, error) {
	if p.APIKey == "" {
		return nil, nil
	}
	url := p.URL
	if url == "" {
		url = abuseIPDBBlacklistURL
	}
	ctx, cancel := context.WithTimeout(ctx, defaultFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", p.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("abuseipdb: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("abuseipdb: unexpected status %s", resp.Status)
	}

	var body struct {
		Data []struct {
			IPAddress            string `json:"ipAddress"`
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("abuseipdb: decode response: %w", err)
	}

	entries := make([]Entry, 0, len(body.Data))
	for _, d := range body.Data {
		addr, err := netip.ParseAddr(d.IPAddress)
		if err != nil {
			continue
		}
		entries = append(entries, Entry{
			Prefix:   netip.PrefixFrom(addr, addr.BitLen()),
			Reason:   fmt.Sprintf("abuseipdb confidence %d%%", d.AbuseConfidenceScore),
			Provider: "abuseipdb",
		})
	}
	return entries, nil
}
