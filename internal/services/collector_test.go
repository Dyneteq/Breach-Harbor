package services

import (
	"testing"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/models"

	"gorm.io/gorm"
)

func newTestCollectorService(t *testing.T) *CollectorService {
	t.Helper()
	db := openTestDB(t)
	loc := testLocationService(t, db)
	return NewCollectorService(db, loc)
}

func TestCreateCollector_TokenIsHashedNotStored(t *testing.T) {
	svc := newTestCollectorService(t)
	user := createTestUser(t, svc.db)

	collector, token, err := svc.CreateCollector(user.ID, "web-1", "203.0.113.10")
	if err != nil {
		t.Fatalf("CreateCollector: %v", err)
	}
	if token == "" {
		t.Fatal("expected a non-empty plaintext token")
	}
	if collector.TokenHash == "" {
		t.Fatal("expected a non-empty token hash on the stored record")
	}
	if collector.TokenHash == token {
		t.Error("TokenHash must not equal the plaintext token")
	}
	if collector.TokenHash != hashToken(token) {
		t.Error("stored TokenHash does not match hashToken(plaintext)")
	}

	// The plaintext is never persisted or recoverable — re-reading the
	// same row from the DB must not carry it either.
	var reloaded models.Collector
	if err := svc.db.First(&reloaded, collector.ID).Error; err != nil {
		t.Fatalf("reload collector: %v", err)
	}
	if reloaded.TokenHash != collector.TokenHash {
		t.Errorf("reloaded TokenHash = %q, want %q", reloaded.TokenHash, collector.TokenHash)
	}
}

func TestValidateCollectorToken(t *testing.T) {
	svc := newTestCollectorService(t)
	user := createTestUser(t, svc.db)
	_, token, err := svc.CreateCollector(user.ID, "web-1", "203.0.113.10")
	if err != nil {
		t.Fatalf("CreateCollector: %v", err)
	}

	if _, err := svc.ValidateCollectorToken(token); err != nil {
		t.Errorf("ValidateCollectorToken(correct token): %v", err)
	}
	if _, err := svc.ValidateCollectorToken(token + "x"); err == nil {
		t.Error("expected ValidateCollectorToken to reject a wrong token")
	}
	if _, err := svc.ValidateCollectorToken(""); err == nil {
		t.Error("expected ValidateCollectorToken to reject an empty token")
	}
}

func TestDeleteCollector_ScopedToUser(t *testing.T) {
	svc := newTestCollectorService(t)
	owner := createTestUser(t, svc.db)
	other := models.User{Email: "other@example.com", Password: "hashed"}
	if err := svc.db.Create(&other).Error; err != nil {
		t.Fatalf("create other user: %v", err)
	}
	if _, _, err := svc.CreateCollector(owner.ID, "web-1", "203.0.113.10"); err != nil {
		t.Fatalf("CreateCollector: %v", err)
	}

	if err := svc.DeleteCollector(other.ID, "web-1"); err != gorm.ErrRecordNotFound {
		t.Errorf("expected gorm.ErrRecordNotFound deleting another user's collector, got %v", err)
	}
	if err := svc.DeleteCollector(owner.ID, "web-1"); err != nil {
		t.Errorf("DeleteCollector(owner): %v", err)
	}
	if _, err := svc.GetCollectorByName(owner.ID, "web-1"); err == nil {
		t.Error("expected the collector to be gone after DeleteCollector")
	}
}

func TestGetCollectorByID_NoUserScoping(t *testing.T) {
	svc := newTestCollectorService(t)
	user := createTestUser(t, svc.db)
	collector, _, err := svc.CreateCollector(user.ID, "web-1", "203.0.113.10")
	if err != nil {
		t.Fatalf("CreateCollector: %v", err)
	}

	got, err := svc.GetCollectorByID(collector.ID)
	if err != nil {
		t.Fatalf("GetCollectorByID: %v", err)
	}
	if got.Name != "web-1" {
		t.Errorf("Name = %q, want web-1", got.Name)
	}
}

func TestCreateIncidentsBatch(t *testing.T) {
	svc := newTestCollectorService(t)
	user := createTestUser(t, svc.db)
	_, token, err := svc.CreateCollector(user.ID, "web-1", "203.0.113.10")
	if err != nil {
		t.Fatalf("CreateCollector: %v", err)
	}

	obs := []ObservationInput{
		{IP: "198.51.100.1", IncidentType: "ssh_failed_login", HappenedAt: time.Now()},
		{IP: "198.51.100.2", IncidentType: "http_suspicious", HappenedAt: time.Now()},
		{IP: "198.51.100.1", IncidentType: "ssh_failed_login", HappenedAt: time.Now()}, // same IP twice
	}

	incidents, err := svc.CreateIncidentsBatch(token, obs)
	if err != nil {
		t.Fatalf("CreateIncidentsBatch: %v", err)
	}
	if len(incidents) != 3 {
		t.Fatalf("expected 3 incidents, got %d", len(incidents))
	}

	var count int64
	svc.db.Model(&models.Incident{}).Where("user_id = ?", user.ID).Count(&count)
	if count != 3 {
		t.Errorf("expected 3 rows persisted, got %d", count)
	}

	var ipCount int64
	svc.db.Model(&models.IPAddress{}).Where("ip = ?", "198.51.100.1").Count(&ipCount)
	if ipCount != 1 {
		t.Errorf("expected the repeated IP to resolve to exactly 1 IPAddress row, got %d", ipCount)
	}
}

func TestMarkEnrolled(t *testing.T) {
	svc := newTestCollectorService(t)
	user := createTestUser(t, svc.db)
	collector, _, err := svc.CreateCollector(user.ID, "web-1", "203.0.113.10")
	if err != nil {
		t.Fatalf("CreateCollector: %v", err)
	}
	if collector.EnrolledAt != nil {
		t.Fatal("expected a freshly created collector to have a nil EnrolledAt")
	}

	if err := svc.MarkEnrolled(collector.ID); err != nil {
		t.Fatalf("MarkEnrolled: %v", err)
	}

	got, err := svc.GetCollectorByID(collector.ID)
	if err != nil {
		t.Fatalf("GetCollectorByID: %v", err)
	}
	if got.EnrolledAt == nil {
		t.Fatal("expected EnrolledAt to be set after MarkEnrolled")
	}
	if got.LastOnline != nil {
		t.Error("expected LastOnline to remain nil — MarkEnrolled must not imply data has flowed")
	}
}

func TestRecordHeartbeat(t *testing.T) {
	svc := newTestCollectorService(t)
	user := createTestUser(t, svc.db)
	collector, _, err := svc.CreateCollector(user.ID, "web-1", "203.0.113.10")
	if err != nil {
		t.Fatalf("CreateCollector: %v", err)
	}
	if collector.LastHeartbeat != nil {
		t.Fatal("expected a freshly created collector to have a nil LastHeartbeat")
	}

	if err := svc.RecordHeartbeat(collector.ID); err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}

	got, err := svc.GetCollectorByID(collector.ID)
	if err != nil {
		t.Fatalf("GetCollectorByID: %v", err)
	}
	if got.LastHeartbeat == nil {
		t.Fatal("expected LastHeartbeat to be set after RecordHeartbeat")
	}
	if got.EnrolledAt != nil {
		t.Error("expected EnrolledAt to remain nil — RecordHeartbeat is independent of enrollment tracking")
	}
	if got.LastOnline != nil {
		t.Error("expected LastOnline to remain nil — a heartbeat is not real incident data")
	}
}

func TestRecordFirewallStatus(t *testing.T) {
	svc := newTestCollectorService(t)
	user := createTestUser(t, svc.db)
	collector, _, err := svc.CreateCollector(user.ID, "web-1", "203.0.113.10")
	if err != nil {
		t.Fatalf("CreateCollector: %v", err)
	}
	if collector.FirewallBackend != "" || collector.FirewallUpdatedAt != nil {
		t.Fatal("expected a freshly created collector to have no firewall status yet")
	}

	if err := svc.RecordFirewallStatus(collector.ID, "nftables", true, []string{"203.0.113.44", "198.51.100.1"}); err != nil {
		t.Fatalf("RecordFirewallStatus: %v", err)
	}

	got, err := svc.GetCollectorByID(collector.ID)
	if err != nil {
		t.Fatalf("GetCollectorByID: %v", err)
	}
	if got.FirewallBackend != "nftables" {
		t.Errorf("FirewallBackend = %q, want nftables", got.FirewallBackend)
	}
	if !got.FirewallEnforcing {
		t.Error("expected FirewallEnforcing to be true")
	}
	if len(got.FirewallBlockedIPs) != 2 {
		t.Errorf("FirewallBlockedIPs = %v, want 2 entries", got.FirewallBlockedIPs)
	}
	if got.FirewallUpdatedAt == nil {
		t.Fatal("expected FirewallUpdatedAt to be set")
	}

	// A later report with enforcing=false and no blocked IPs must
	// actually clear the previous snapshot, not silently keep it —
	// GORM's Updates(struct) skips zero-valued fields by default,
	// which RecordFirewallStatus's explicit Select must override.
	if err := svc.RecordFirewallStatus(collector.ID, "nftables", false, nil); err != nil {
		t.Fatalf("RecordFirewallStatus (second call): %v", err)
	}
	got2, err := svc.GetCollectorByID(collector.ID)
	if err != nil {
		t.Fatalf("GetCollectorByID: %v", err)
	}
	if got2.FirewallEnforcing {
		t.Error("expected FirewallEnforcing to be cleared to false")
	}
	if len(got2.FirewallBlockedIPs) != 0 {
		t.Errorf("FirewallBlockedIPs = %v, want empty after re-reporting with none blocked", got2.FirewallBlockedIPs)
	}
}

func TestCreateIncidentsBatch_InvalidToken(t *testing.T) {
	svc := newTestCollectorService(t)
	if _, err := svc.CreateIncidentsBatch("not-a-real-token", []ObservationInput{{IP: "198.51.100.1", IncidentType: "x"}}); err == nil {
		t.Error("expected an error for an invalid collector token")
	}
}
