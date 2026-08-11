package feed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const spamhausFixture = `; Spamhaus DROP list
; Last updated 2026-08-11
1.10.16.0/20 ; SBL256894
5.42.92.0/23 ; SBL456789
`

func TestSpamhaus_Fetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(spamhausFixture))
	}))
	defer srv.Close()

	p := &Spamhaus{URL: srv.URL}
	entries, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(entries), entries)
	}
	if entries[0].Prefix.String() != "1.10.16.0/20" {
		t.Errorf("entries[0].Prefix = %s, want 1.10.16.0/20", entries[0].Prefix)
	}
	if entries[0].Provider != "spamhaus" {
		t.Errorf("entries[0].Provider = %q, want spamhaus", entries[0].Provider)
	}
}

func TestSpamhaus_Fetch_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := &Spamhaus{URL: srv.URL}
	if _, err := p.Fetch(context.Background()); err == nil {
		t.Fatal("expected an error on a 500 response")
	}
}

func TestParseSpamhausDrop_IgnoresCommentsAndBlankLines(t *testing.T) {
	entries := parseSpamhausDrop([]byte("\n; comment\n\n203.0.113.0/24 ; SBL1\n"))
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(entries), entries)
	}
}
