package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/config"
)

// newTestServer builds a fully-wired *Server against a throwaway temp
// data dir and SQLite DB, with the dashboard disabled (Config.Web =
// false) so tests never need templates/static on disk relative to
// their own package directory (see PLAN.md's note on TemplatesDir/
// StaticDir being overridable for exactly this reason).
func newTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()

	cfg := DefaultConfig()
	cfg.DataDir = dir
	cfg.DBPath = filepath.Join(dir, "breach_harbor.db")
	cfg.Web = false
	cfg.PublishInterval = time.Hour // never fires on its own during a test

	appCfg := &config.Config{
		JWT:     config.JWTConfig{Secret: "test-secret", ExpiryMinutes: 60},
		MaxMind: config.MaxMindConfig{DBPath: filepath.Join(dir, "missing-city.mmdb"), ASNDBPath: filepath.Join(dir, "missing-asn.mmdb")},
	}

	srv, err := New(cfg, appCfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}

func TestHealth(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", rec.Code)
	}
}

func TestHandleGetBlocklist_NotYetPublished(t *testing.T) {
	srv := newTestServer(t)
	_, token := createTestUserAndCollector(t, srv, "web-1")

	req := httptest.NewRequest(http.MethodGet, "/v1/blocklist", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("code = %d, want 503 before any publish has happened", rec.Code)
	}
}

func TestHandleObservations_RequiresValidToken(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/observations", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", rec.Code)
	}
}

func TestConfirmedFromIncidents_RequiresThreshold(t *testing.T) {
	srv := newTestServer(t)
	_, token := createTestUserAndCollector(t, srv, "web-1")
	ctx := context.Background()

	// Below threshold (consensusIncidentThreshold = 3): two incidents
	// for the same IP must not be confirmed.
	if _, err := srv.collectorService.CreateIncidentsBatch(token, twoObservations("203.0.113.44")); err != nil {
		t.Fatalf("CreateIncidentsBatch: %v", err)
	}
	entries, err := srv.confirmedFromIncidents(ctx)
	if err != nil {
		t.Fatalf("confirmedFromIncidents: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 confirmed entries below threshold, got %d: %+v", len(entries), entries)
	}

	// One more pushes it to 3, at threshold.
	if _, err := srv.collectorService.CreateIncidentsBatch(token, twoObservations("203.0.113.44")[:1]); err != nil {
		t.Fatalf("CreateIncidentsBatch: %v", err)
	}
	entries, err = srv.confirmedFromIncidents(ctx)
	if err != nil {
		t.Fatalf("confirmedFromIncidents: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 confirmed entry at threshold, got %d: %+v", len(entries), entries)
	}
	if entries[0].Prefix.Addr().String() != "203.0.113.44" {
		t.Errorf("Prefix = %s, want 203.0.113.44/32", entries[0].Prefix)
	}
}
