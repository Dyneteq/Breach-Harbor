package feed

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// fakeProvider lets tests script success/failure across calls without
// touching the network.
type fakeProvider struct {
	name    string
	calls   int
	fetch   func(calls int) ([]Entry, error)
	needed  bool
	confged bool
}

func (f *fakeProvider) Name() string              { return f.name }
func (f *fakeProvider) RequiresKey() (bool, bool) { return f.needed, f.confged }
func (f *fakeProvider) Fetch(ctx context.Context) ([]Entry, error) {
	f.calls++
	return f.fetch(f.calls)
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCachedProvider_ServesFromCacheWithinTTL(t *testing.T) {
	dir := t.TempDir()
	fp := &fakeProvider{name: "test", fetch: func(calls int) ([]Entry, error) {
		return []Entry{{Prefix: mustPrefix(t, "203.0.113.0/24"), Provider: "test"}}, nil
	}}
	c := NewCachedProvider(fp, dir, 0)

	if _, err := c.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fp.calls != 1 {
		t.Errorf("expected only 1 live fetch (second call served from cache), got %d", fp.calls)
	}
}

func TestCachedProvider_FallsBackToLastGoodOnFailure(t *testing.T) {
	dir := t.TempDir()
	fail := false
	fp := &fakeProvider{name: "test", fetch: func(calls int) ([]Entry, error) {
		if fail {
			return nil, errors.New("network down")
		}
		return []Entry{{Prefix: mustPrefix(t, "203.0.113.0/24"), Provider: "test"}}, nil
	}}
	// A 1ns TTL (NewCachedProvider treats an actual 0 as "use the
	// default") expires immediately, so every call attempts a live
	// fetch instead of serving straight from cache.
	c := NewCachedProvider(fp, dir, 1)

	first, err := c.Fetch(context.Background())
	if err != nil || len(first) != 1 {
		t.Fatalf("first fetch = %v, %v, want 1 entry, nil", first, err)
	}

	fail = true
	second, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatalf("expected the cache fallback to swallow the network error, got %v", err)
	}
	if len(second) != 1 || second[0].Prefix.String() != "203.0.113.0/24" {
		t.Errorf("expected the last-good cached entry to be served, got %+v", second)
	}
}

func TestCachedProvider_NoCacheAndFetchFails_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	fp := &fakeProvider{name: "test", fetch: func(calls int) ([]Entry, error) {
		return nil, errors.New("network down")
	}}
	c := NewCachedProvider(fp, dir, 0)

	if _, err := c.Fetch(context.Background()); err == nil {
		t.Fatal("expected an error when there is no cache to fall back to")
	}
}

func TestCachedProvider_EmptyResultDoesNotClobberGoodCache(t *testing.T) {
	dir := t.TempDir()
	returnEmpty := false
	fp := &fakeProvider{name: "test", fetch: func(calls int) ([]Entry, error) {
		if returnEmpty {
			return nil, nil
		}
		return []Entry{{Prefix: mustPrefix(t, "203.0.113.0/24"), Provider: "test"}}, nil
	}}
	c := NewCachedProvider(fp, dir, 1)

	if _, err := c.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	returnEmpty = true
	entries, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("expected the previous good cache to be preserved instead of an empty result, got %d entries", len(entries))
	}
}
