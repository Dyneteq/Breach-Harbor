package feed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAbuseIPDB_Fetch_NoKeyConfigured(t *testing.T) {
	p := NewAbuseIPDB("")
	needed, configured := p.RequiresKey()
	if !needed || configured {
		t.Errorf("RequiresKey() = %v, %v, want true, false", needed, configured)
	}
	entries, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("expected no error when no key is configured, got %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected zero entries with no key, got %d", len(entries))
	}
}

func TestAbuseIPDB_Fetch_WithKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "test-key" {
			t.Errorf("expected Key header to be set, got %q", r.Header.Get("Key"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":[{"ipAddress":"203.0.113.5","abuseConfidenceScore":97}]}`))
	}))
	defer srv.Close()

	p := &AbuseIPDB{URL: srv.URL, APIKey: "test-key"}
	entries, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(entries), entries)
	}
	if entries[0].Provider != "abuseipdb" {
		t.Errorf("Provider = %q, want abuseipdb", entries[0].Provider)
	}
}
