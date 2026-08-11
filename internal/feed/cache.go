package feed

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const defaultTTL = 15 * time.Minute

// CachedProvider wraps a Provider with an on-disk TTL cache at
// <data-dir>/feeds/<name>.json. Within the TTL, Fetch is served
// entirely from disk (no network call). Once stale, it attempts a
// live Fetch; on success the cache is refreshed, on failure the
// last-good cache is served regardless of age — "cache first, ask
// later" applies here just as much as it does to blocklist fetch/
// verify in M2.
type CachedProvider struct {
	Provider Provider
	DataDir  string
	TTL      time.Duration
}

// NewCachedProvider wraps p. ttl <= 0 uses defaultTTL (15m).
func NewCachedProvider(p Provider, dataDir string, ttl time.Duration) *CachedProvider {
	if ttl <= 0 {
		ttl = defaultTTL
	}
	return &CachedProvider{Provider: p, DataDir: dataDir, TTL: ttl}
}

func (c *CachedProvider) Name() string { return c.Provider.Name() }

func (c *CachedProvider) RequiresKey() (needed, configured bool) { return c.Provider.RequiresKey() }

type cacheFile struct {
	FetchedAt time.Time `json:"fetched_at"`
	Entries   []Entry   `json:"entries"`
}

func (c *CachedProvider) path() string {
	return filepath.Join(c.DataDir, "feeds", c.Provider.Name()+".json")
}

func (c *CachedProvider) Fetch(ctx context.Context) ([]Entry, error) {
	if cached, ok := c.readCache(); ok && time.Since(cached.FetchedAt) < c.TTL {
		return cached.Entries, nil
	}

	entries, err := c.Provider.Fetch(ctx)
	if err != nil {
		if cached, ok := c.readCache(); ok {
			return cached.Entries, nil
		}
		return nil, err
	}

	// A provider that isn't configured (e.g. AbuseIPDB with no key)
	// legitimately returns zero entries with no error — don't
	// overwrite a previously-cached good result with an empty one.
	if len(entries) == 0 {
		if cached, ok := c.readCache(); ok {
			return cached.Entries, nil
		}
		return entries, nil
	}

	_ = c.writeCache(entries) // a failed cache write must not fail the caller's Fetch
	return entries, nil
}

func (c *CachedProvider) readCache() (cacheFile, bool) {
	data, err := os.ReadFile(c.path())
	if err != nil {
		return cacheFile{}, false
	}
	var cf cacheFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return cacheFile{}, false
	}
	return cf, true
}

func (c *CachedProvider) writeCache(entries []Entry) error {
	if err := os.MkdirAll(filepath.Dir(c.path()), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cacheFile{FetchedAt: time.Now(), Entries: entries}, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, c.path())
}

var _ Provider = (*CachedProvider)(nil)
