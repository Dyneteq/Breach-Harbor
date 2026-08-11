package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/blocklist"
	"github.com/Dyneteq/Breach-Harbor/internal/store"
)

func newTestStore(t *testing.T) store.AgentStore {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestUploadPending_NothingQueuedIsANoop(t *testing.T) {
	st := newTestStore(t)
	u := NewUploader(st, Enrollment{ServerURL: "http://unused.invalid", Token: "t"})
	n, err := u.UploadPending(context.Background())
	if err != nil || n != 0 {
		t.Errorf("UploadPending on an empty queue = (%d, %v), want (0, nil)", n, err)
	}
}

func TestUploadPending_FailureDoesNotAck(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	st := newTestStore(t)
	if err := st.Enqueue(store.Observation{IP: netip.MustParseAddr("203.0.113.44"), Kind: "ssh_failed_login", Time: time.Now()}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	u := NewUploader(st, Enrollment{ServerURL: ts.URL, Token: "t"})
	u.Client = ts.Client()

	if _, err := u.UploadPending(context.Background()); err == nil {
		t.Fatal("expected an error when the server returns 500")
	}
	if depth, _ := st.QueueDepth(); depth != 1 {
		t.Errorf("queue depth after a failed upload = %d, want 1 (nothing Acked)", depth)
	}
}

func TestRefreshBlocklist_NoCacheOnFailure_ReturnsLocalOnly(t *testing.T) {
	st := newTestStore(t)
	u := NewUploader(st, Enrollment{ServerURL: "http://127.0.0.1:1", Token: "t", PublicKey: []byte("not-a-real-key")})

	local := []blocklist.Entry{{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Reason: "local"}}
	merged, err := u.RefreshBlocklist(context.Background(), local)
	if err == nil {
		t.Fatal("expected an error when the server is unreachable and there's no cache")
	}
	if len(merged) != 1 || merged[0].Reason != "local" {
		t.Errorf("expected merged to equal local entries with no cache, got %+v", merged)
	}
}

func TestRefreshBlocklist_FallsBackToCacheOnFailure(t *testing.T) {
	st := newTestStore(t)
	cached := blocklist.SignedBlocklist{
		Blocklist: blocklist.Blocklist{
			Version:     1,
			GeneratedAt: time.Now().Add(-time.Hour),
			Entries:     []blocklist.Entry{{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Reason: "cached"}},
		},
	}
	if err := st.SaveBlocklist(cached); err != nil {
		t.Fatalf("SaveBlocklist: %v", err)
	}

	u := NewUploader(st, Enrollment{ServerURL: "http://127.0.0.1:1", Token: "t", PublicKey: []byte("not-a-real-key")})
	local := []blocklist.Entry{{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Reason: "local"}}

	merged, err := u.RefreshBlocklist(context.Background(), local)
	if err == nil {
		t.Fatal("expected a non-nil error even though a cached copy was served")
	}
	if !containsReason(merged, "cached") || !containsReason(merged, "local") {
		t.Errorf("expected merged to contain both the cached and local entries, got %+v", merged)
	}
}

func containsReason(entries []blocklist.Entry, reason string) bool {
	for _, e := range entries {
		if e.Reason == reason {
			return true
		}
	}
	return false
}
