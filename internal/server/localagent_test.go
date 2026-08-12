package server

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/config"
	"github.com/Dyneteq/Breach-Harbor/internal/store"
)

func TestLocalAgentManager_StartStopEnforce(t *testing.T) {
	srv := newTestServer(t)
	user, err := srv.authService.Register("local-agent@example.com", "password123", "L", "A")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := srv.localAgent.Start(user.ID); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.localAgent.StopIfRunning() })

	status := srv.localAgent.Status()
	if !status.Running {
		t.Fatal("expected Running=true after Start")
	}
	if status.Enforcing {
		t.Fatal("expected Enforcing=false immediately after Start — it always starts dry-run")
	}
	wantCollector := localAgentCollectorName(user.ID)
	if status.CollectorName != wantCollector {
		t.Errorf("CollectorName = %q, want %q", status.CollectorName, wantCollector)
	}

	// Starting again while already running is an error and doesn't
	// disturb the existing run.
	if err := srv.localAgent.Start(user.ID); err == nil {
		t.Fatal("expected error starting an already-running local agent")
	}

	collector, err := srv.collectorService.GetCollectorByName(user.ID, wantCollector)
	if err != nil {
		t.Fatalf("GetCollectorByName: %v", err)
	}
	if collector.IP != "127.0.0.1" {
		t.Errorf("collector IP = %q, want 127.0.0.1", collector.IP)
	}

	if err := srv.localAgent.SetEnforce(user.ID, true); err != nil {
		t.Fatalf("SetEnforce(true): %v", err)
	}
	if !srv.localAgent.Status().Enforcing {
		t.Fatal("expected Enforcing=true after SetEnforce(true)")
	}

	if err := srv.localAgent.Stop(user.ID); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	status = srv.localAgent.Status()
	if status.Running {
		t.Fatal("expected Running=false after Stop")
	}
	if status.Enforcing {
		t.Fatal("expected Enforcing=false after Stop")
	}

	if err := srv.localAgent.Stop(user.ID); err == nil {
		t.Fatal("expected error stopping an already-stopped local agent")
	}
	if err := srv.localAgent.SetEnforce(user.ID, true); err == nil {
		t.Fatal("expected error enforcing a stopped local agent")
	}
}

// TestLocalAgentManager_DisabledByDefault confirms every method
// refuses to act unless the operator explicitly opted in — this app
// has open self-registration and no admin/role concept, so this gate
// is what stands between "any new signup" and "can flip this host's
// own firewall into enforcing."
func TestLocalAgentManager_DisabledByDefault(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.DataDir = dir
	cfg.DBPath = dir + "/breach_harbor.db"
	cfg.Web = false
	cfg.PublishInterval = time.Hour
	// cfg.LocalAgentEnabled left false: the point of this test.

	appCfg := &config.Config{
		JWT:     config.JWTConfig{Secret: "test-secret", ExpiryMinutes: 60},
		MaxMind: config.MaxMindConfig{DBPath: dir + "/missing-city.mmdb", ASNDBPath: dir + "/missing-asn.mmdb"},
	}
	srv, err := New(cfg, appCfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	defer srv.Close()

	user, err := srv.authService.Register("disabled@example.com", "password123", "D", "I")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := srv.localAgent.Start(user.ID); !errors.Is(err, ErrLocalAgentDisabled) {
		t.Errorf("Start: got %v, want ErrLocalAgentDisabled", err)
	}
	if status := srv.localAgent.Status(); status.Enabled {
		t.Error("expected Status().Enabled=false")
	}
}

// TestLocalAgentManager_OnlyStarterCanStopOrEnforce confirms one
// logged-in user can't stop or reconfigure another user's already
// running local agent (an IDOR the manager itself must reject, since
// both users pass the same WebAuthMiddleware check).
func TestLocalAgentManager_OnlyStarterCanStopOrEnforce(t *testing.T) {
	srv := newTestServer(t)
	owner, err := srv.authService.Register("owner@example.com", "password123", "O", "W")
	if err != nil {
		t.Fatalf("Register(owner): %v", err)
	}
	other, err := srv.authService.Register("other@example.com", "password123", "O", "T")
	if err != nil {
		t.Fatalf("Register(other): %v", err)
	}

	if err := srv.localAgent.Start(owner.ID); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.localAgent.StopIfRunning() })

	if err := srv.localAgent.SetEnforce(other.ID, true); !errors.Is(err, ErrLocalAgentNotOwner) {
		t.Errorf("SetEnforce by non-owner: got %v, want ErrLocalAgentNotOwner", err)
	}
	if srv.localAgent.Status().Enforcing {
		t.Error("a non-owner's SetEnforce must not have taken effect")
	}
	if err := srv.localAgent.Stop(other.ID); !errors.Is(err, ErrLocalAgentNotOwner) {
		t.Errorf("Stop by non-owner: got %v, want ErrLocalAgentNotOwner", err)
	}
	if !srv.localAgent.Status().Running {
		t.Error("a non-owner's Stop must not have taken effect")
	}

	// The actual owner can still do both.
	if err := srv.localAgent.SetEnforce(owner.ID, true); err != nil {
		t.Errorf("SetEnforce by owner: %v", err)
	}
	if err := srv.localAgent.Stop(owner.ID); err != nil {
		t.Errorf("Stop by owner: %v", err)
	}
}

// TestLocalAgentManager_RestartReusesCollector confirms a second
// Start (after Stop) reuses the same per-user collector instead of
// colliding with models.Collector.Name's global-unique constraint.
func TestLocalAgentManager_RestartReusesCollector(t *testing.T) {
	srv := newTestServer(t)
	user, err := srv.authService.Register("restart@example.com", "password123", "R", "S")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := srv.localAgent.Start(user.ID); err != nil {
		t.Fatalf("Start (1st): %v", err)
	}
	firstID := srv.localAgent.Status()
	if err := srv.localAgent.Stop(user.ID); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if err := srv.localAgent.Start(user.ID); err != nil {
		t.Fatalf("Start (2nd): %v", err)
	}
	t.Cleanup(func() { _ = srv.localAgent.StopIfRunning() })
	second := srv.localAgent.Status()

	if second.CollectorName != firstID.CollectorName {
		t.Errorf("collector name changed across restarts: %q vs %q", firstID.CollectorName, second.CollectorName)
	}

	collectors, err := srv.collectorService.GetCollectorsByUserID(user.ID)
	if err != nil {
		t.Fatalf("GetCollectorsByUserID: %v", err)
	}
	if len(collectors) != 1 {
		t.Fatalf("got %d collectors after two Start/Stop cycles, want exactly 1", len(collectors))
	}
}

// TestLocalAgentManager_DrainPersistsObservations exercises the
// in-process hand-off from the local agent's own store queue to
// collectorService, bypassing the 10s ticker by calling drainOnce
// directly.
func TestLocalAgentManager_DrainPersistsObservations(t *testing.T) {
	srv := newTestServer(t)
	user, err := srv.authService.Register("drain@example.com", "password123", "D", "R")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := srv.localAgent.Start(user.ID); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.localAgent.StopIfRunning() })

	ip := netip.MustParseAddr("203.0.113.9")
	if err := srv.localAgent.st.Enqueue(store.Observation{IP: ip, Kind: "ssh_failed_login", Time: time.Now()}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	srv.localAgent.drainOnce(srv.localAgent.st, srv.localAgent.collectorID)

	incidents, err := srv.collectorService.GetIncidentsByUserID(user.ID)
	if err != nil {
		t.Fatalf("GetIncidentsByUserID: %v", err)
	}
	if len(incidents) != 1 {
		t.Fatalf("got %d incidents, want 1", len(incidents))
	}
	if incidents[0].IPAddress.IP != ip.String() {
		t.Errorf("incident IP = %q, want %q", incidents[0].IPAddress.IP, ip.String())
	}

	depth, err := srv.localAgent.st.QueueDepth()
	if err != nil {
		t.Fatalf("QueueDepth: %v", err)
	}
	if depth != 0 {
		t.Errorf("queue depth = %d after a successful drain, want 0 (acked)", depth)
	}
}
