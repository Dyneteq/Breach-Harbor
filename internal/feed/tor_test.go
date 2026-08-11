package feed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const torFixture = "203.0.113.5\n198.51.100.9\n"

func TestTor_Fetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(torFixture))
	}))
	defer srv.Close()

	p := &Tor{URL: srv.URL}
	entries, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(entries), entries)
	}
	if entries[0].Prefix.Bits() != 32 {
		t.Errorf("expected an exact /32 for a Tor exit IP, got %s", entries[0].Prefix)
	}
	if entries[0].Reason != "tor exit node" {
		t.Errorf("Reason = %q, want %q", entries[0].Reason, "tor exit node")
	}
}
