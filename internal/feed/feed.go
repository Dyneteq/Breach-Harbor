// Package feed provides pluggable free threat-intel providers
// (Spamhaus DROP, FireHOL level1, Tor exit nodes, AbuseIPDB) that the
// agent cross-references against IPs it has already observed via
// internal/logsource. cache.go wraps every provider with an on-disk
// TTL cache so a network hiccup never removes protection the agent
// already had — a failed Fetch serves the last-good cache.
package feed

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"
)

// Entry is one threat-intel-listed range. netip.Prefix implements
// encoding.TextMarshaler/TextUnmarshaler, so this round-trips through
// cache.go's JSON cache file without any custom marshaling.
type Entry struct {
	Prefix   netip.Prefix `json:"prefix"`
	Reason   string       `json:"reason"`
	Provider string       `json:"provider"`
}

// Provider is a single pluggable feed source.
type Provider interface {
	// Name is a short identifier, e.g. "spamhaus" or "abuseipdb".
	Name() string

	// RequiresKey reports whether this provider needs an API key
	// (needed) and whether one has been configured (configured). A
	// provider that needs a key but doesn't have one returns an empty
	// result from Fetch rather than an error — it's off, not broken.
	RequiresKey() (needed, configured bool)

	// Fetch returns the provider's current entries. It must use a
	// bounded timeout and must never be fatal to the caller — network
	// failures are expected and handled by cache.go's fallback.
	Fetch(ctx context.Context) ([]Entry, error)
}

// defaultFetchTimeout bounds every provider's HTTP call regardless of
// what timeout (if any) the caller's context carries.
const defaultFetchTimeout = 15 * time.Second

// httpClient is shared across providers; tests point providers at an
// httptest.Server via each provider's URL field rather than mocking
// this client.
var httpClient = &http.Client{}

// fetchURL performs a bounded-timeout GET and returns the response
// body, erroring on any non-200 status.
func fetchURL(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: unexpected status %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}
