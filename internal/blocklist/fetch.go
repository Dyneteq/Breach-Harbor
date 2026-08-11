package blocklist

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// defaultFetchTimeout bounds the agent's GET /v1/blocklist call — a
// slow/hanging server must never stall the agent's own event loop.
const defaultFetchTimeout = 15 * time.Second

// FetchAndVerify GETs the signed blocklist from serverURL and verifies
// it against trustedPublicKey before returning it. Any failure —
// network, non-200, or a bad signature — is returned as an error and
// changes nothing on disk; it is the caller's job (internal/agent/
// enroll.go) to fall back to the last-good cached copy, keeping "cache
// first, ask later" out of this function so it stays a pure,
// httptest-friendly fetch.
func FetchAndVerify(ctx context.Context, client *http.Client, serverURL, token string, trustedPublicKey []byte) (*Blocklist, error) {
	if client == nil {
		client = &http.Client{}
	}
	url := strings.TrimRight(serverURL, "/") + "/v1/blocklist"

	ctx, cancel := context.WithTimeout(ctx, defaultFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch blocklist: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("fetch blocklist: server returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var signed SignedBlocklist
	if err := json.NewDecoder(resp.Body).Decode(&signed); err != nil {
		return nil, fmt.Errorf("fetch blocklist: decode response: %w", err)
	}

	if err := NewVerifier().Verify(signed.Blocklist, signed.Signature, trustedPublicKey); err != nil {
		return nil, fmt.Errorf("fetch blocklist: %w", err)
	}

	return &signed.Blocklist, nil
}

// Merge unions local (agent-synthesized) entries with server-fetched
// ones, deduplicating by prefix — "union, never overwrite" (PLAN.md M2
// item 7), so a fetched blocklist can never remove protection the
// agent already had on its own.
func Merge(local, fromServer []Entry) []Entry {
	seen := make(map[string]bool, len(local)+len(fromServer))
	merged := make([]Entry, 0, len(local)+len(fromServer))
	for _, e := range append(append([]Entry{}, local...), fromServer...) {
		key := e.Prefix.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		merged = append(merged, e)
	}
	return merged
}
