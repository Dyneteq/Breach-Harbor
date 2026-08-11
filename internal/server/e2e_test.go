package server

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/agent"
	"github.com/Dyneteq/Breach-Harbor/internal/blocklist"
	"github.com/Dyneteq/Breach-Harbor/internal/models"
	"github.com/Dyneteq/Breach-Harbor/internal/services"
	"github.com/Dyneteq/Breach-Harbor/internal/store"
)

// createTestUserAndCollector registers a user directly through
// services (bypassing HTTP — that surface is covered by its own
// handler/route tests) and creates one collector for it, returning the
// collector and its one-time plaintext token.
func createTestUserAndCollector(t *testing.T, srv *Server, name string) (models.Collector, string) {
	t.Helper()
	user, err := srv.authService.Register("e2e@example.com", "password123", "E", "2E")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	collector, token, err := srv.collectorService.CreateCollector(user.ID, name, "203.0.113.1")
	if err != nil {
		t.Fatalf("CreateCollector: %v", err)
	}
	return *collector, token
}

func twoObservations(ip string) []services.ObservationInput {
	return []services.ObservationInput{
		{IP: ip, IncidentType: "ssh_failed_login", HappenedAt: time.Now()},
		{IP: ip, IncidentType: "ssh_failed_login", HappenedAt: time.Now()},
	}
}

// TestEndToEnd_EnrollObserveIngestPublishFetchVerifyMerge exercises the
// full M2 loop PLAN.md's demo script describes: an agent enrolls,
// uploads observations, the server aggregates them into a signed
// blocklist, the agent fetches/verifies/merges it — and, the
// specifically-called-out "cache first, ask later" guarantee, keeps
// enforcing the last verified copy after the server becomes
// unreachable. No-op firewall (this test never touches one) and no
// real network (the feed-fetching half of blocklistSource is swapped
// out for the DB-only consensus half), so it's CI-safe.
func TestEndToEnd_EnrollObserveIngestPublishFetchVerifyMerge(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	// Skip the free-feed network calls (spamhaus/firehol/tor) — this
	// test is about the enroll/observe/publish/fetch loop, not feed
	// fetching, which internal/feed already covers on its own.
	srv.publisher.Source = srv.confirmedFromIncidents

	_, token := createTestUserAndCollector(t, srv, "web-1")

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Enroll.
	enrollment, err := agent.Enroll(ctx, ts.Client(), ts.URL, token)
	if err != nil {
		t.Fatalf("agent.Enroll: %v", err)
	}
	if enrollment.CollectorName != "web-1" {
		t.Errorf("CollectorName = %q, want web-1", enrollment.CollectorName)
	}
	if len(enrollment.PublicKey) == 0 {
		t.Fatal("expected a non-empty pinned public key")
	}

	// 2. Observe: queue enough observations of one attacker IP, from
	// the agent's local store, to cross the server's consensus
	// threshold once uploaded.
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	attacker := netip.MustParseAddr("198.51.100.77")
	for i := 0; i < consensusIncidentThreshold; i++ {
		if err := st.Enqueue(store.Observation{IP: attacker, Kind: "ssh_failed_login", Time: time.Now()}); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}

	uploader := agent.NewUploader(st, enrollment)
	uploader.Client = ts.Client()

	// 3. Ingest: upload drains the queue via POST /v1/observations.
	n, err := uploader.UploadPending(ctx)
	if err != nil {
		t.Fatalf("UploadPending: %v", err)
	}
	if n != consensusIncidentThreshold {
		t.Fatalf("uploaded %d observation(s), want %d", n, consensusIncidentThreshold)
	}
	if depth, _ := st.QueueDepth(); depth != 0 {
		t.Errorf("queue depth after a successful upload = %d, want 0 (all Acked)", depth)
	}

	// 4. Publish: force one cycle (the real ticker is 1h in tests).
	srv.publisher.Refresh(ctx)

	// 5. Fetch + verify + merge.
	local := []blocklist.Entry{{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Reason: "local: spamhaus"}}
	merged, err := uploader.RefreshBlocklist(ctx, local)
	if err != nil {
		t.Fatalf("RefreshBlocklist: %v", err)
	}
	if !containsPrefix(merged, "198.51.100.77/32") {
		t.Errorf("expected the merged blocklist to contain the confirmed attacker IP, got %+v", merged)
	}
	if !containsPrefix(merged, "203.0.113.0/24") {
		t.Errorf("expected the merged blocklist to still contain the local-synth entry (union, never replace), got %+v", merged)
	}

	// 6. Kill the server mid-session (PLAN.md's M2 demo): the agent
	// must keep serving its last verified cached blocklist, merged
	// with whatever local entries it's given now.
	ts.Close()
	localAfterOutage := []blocklist.Entry{{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Reason: "local: new detection while server is down"}}
	mergedAfterOutage, err := uploader.RefreshBlocklist(ctx, localAfterOutage)
	if err == nil {
		t.Error("expected RefreshBlocklist to report the fetch failure even while falling back")
	}
	if !containsPrefix(mergedAfterOutage, "198.51.100.77/32") {
		t.Errorf("expected the cached attacker IP to survive a server outage, got %+v", mergedAfterOutage)
	}
	if !containsPrefix(mergedAfterOutage, "192.0.2.0/24") {
		t.Errorf("expected the new local entry to still be present during the outage, got %+v", mergedAfterOutage)
	}
}

func containsPrefix(entries []blocklist.Entry, prefix string) bool {
	want := netip.MustParsePrefix(prefix)
	for _, e := range entries {
		if e.Prefix == want {
			return true
		}
	}
	return false
}
