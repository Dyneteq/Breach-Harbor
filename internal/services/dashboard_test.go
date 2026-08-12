package services

import (
	"testing"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/models"
)

// seedIncidentAt inserts a minimal Incident row with an explicit
// CreatedAt (GORM only auto-populates CreatedAt when it's the zero
// value, so setting it here sticks) — used to control exactly which
// hourly bucket each row should land in.
func seedIncidentAt(t *testing.T, svc *DashboardService, userID uint, at time.Time) {
	t.Helper()
	incident := models.Incident{
		IncidentType: "ssh_failed_login",
		UserID:       userID,
		HappenedAt:   at,
		CreatedAt:    at,
	}
	if err := svc.db.Create(&incident).Error; err != nil {
		t.Fatalf("seed incident: %v", err)
	}
}

func TestHourlyIncidentCounts_GroupsIntoCorrectBuckets(t *testing.T) {
	db := openTestDB(t)
	svc := NewDashboardService(db, testLocationService(t, db))
	user := createTestUser(t, db)

	now := time.Now().UTC()
	seedIncidentAt(t, svc, user.ID, now)
	seedIncidentAt(t, svc, user.ID, now)                       // same hour as above -> bucket count 2
	seedIncidentAt(t, svc, user.ID, now.Add(-3*time.Hour))     // a different, earlier bucket -> count 1
	seedIncidentAt(t, svc, user.ID, now.Add(-30*24*time.Hour)) // far outside the 24h window -> excluded

	hourly, err := svc.hourlyIncidentCounts(user.ID)
	if err != nil {
		t.Fatalf("hourlyIncidentCounts: %v", err)
	}
	if len(hourly) != 24 {
		t.Fatalf("expected exactly 24 hourly buckets, got %d", len(hourly))
	}

	var total int64
	for _, h := range hourly {
		total += h.Count
	}
	if total != 3 {
		t.Errorf("expected 3 incidents counted across all buckets (excluding the 30-day-old one), got %d", total)
	}

	if hourly[0].Count != 2 {
		t.Errorf("expected the current-hour bucket (index 0) to have count 2, got %d", hourly[0].Count)
	}
	if hourly[3].Count != 1 {
		t.Errorf("expected the -3h bucket (index 3) to have count 1, got %d", hourly[3].Count)
	}
}

func TestNewAttackMapEvent_MapsIncidentAndDestinationFields(t *testing.T) {
	happenedAt := time.Now().UTC()
	incident := models.Incident{
		ID:           7,
		IncidentType: "ssh_failed_login",
		HappenedAt:   happenedAt,
		CollectorID:  3,
		Collector:    models.Collector{Name: "web-1"},
		IPAddress: models.IPAddress{
			IP: "203.0.113.10",
			Location: models.Location{
				Latitude:    51.5074,
				Longitude:   -0.1278,
				City:        "London",
				CountryName: "United Kingdom",
			},
		},
	}
	dest := models.Location{Latitude: 37.7749, Longitude: -122.4194}

	event := newAttackMapEvent(incident, dest)

	if event.IncidentID != 7 || event.IncidentType != "ssh_failed_login" {
		t.Errorf("incident fields not mapped: %+v", event)
	}
	if event.SourceIP != "203.0.113.10" || event.SourceCity != "London" || event.SourceCountry != "United Kingdom" {
		t.Errorf("source fields not mapped: %+v", event)
	}
	if event.SourceLat != 51.5074 || event.SourceLon != -0.1278 {
		t.Errorf("source coords not mapped: %+v", event)
	}
	if event.CollectorName != "web-1" {
		t.Errorf("CollectorName = %q, want web-1", event.CollectorName)
	}
	if event.DestLat != 37.7749 || event.DestLon != -122.4194 {
		t.Errorf("dest coords not mapped: %+v", event)
	}
}

// TestGetAttackMapEvents_SkipsIncidentsWithoutUsableLocations covers the
// "null island" guard from both directions: a source IP whose Location was
// never enriched (Latitude/Longitude both zero) is skipped outright, and -
// since this test's LocationService has no MaxMind database configured
// (testLocationService), GetOrCreateLocation(collector.IP) always falls
// back to the same zero-coordinate "Unknown" location - even an incident
// with a real, enriched source is skipped once its destination can't be
// resolved.
func TestGetAttackMapEvents_SkipsIncidentsWithoutUsableLocations(t *testing.T) {
	db := openTestDB(t)
	svc := NewDashboardService(db, testLocationService(t, db))
	user := createTestUser(t, db)
	collector := models.Collector{Name: "web-1", IP: "198.51.100.1", TokenHash: "hash", UserID: user.ID}
	if err := db.Create(&collector).Error; err != nil {
		t.Fatalf("seed collector: %v", err)
	}

	unenriched := models.IPAddress{IP: "203.0.113.10", Location: models.Location{CountryName: "Unknown", CountryCode: "XX"}}
	if err := db.Create(&unenriched).Error; err != nil {
		t.Fatalf("seed unenriched ip address: %v", err)
	}
	enriched := models.IPAddress{IP: "203.0.113.20", Location: models.Location{
		CountryName: "United Kingdom", CountryCode: "GB", City: "London", Latitude: 51.5074, Longitude: -0.1278,
	}}
	if err := db.Create(&enriched).Error; err != nil {
		t.Fatalf("seed enriched ip address: %v", err)
	}

	for _, ip := range []models.IPAddress{unenriched, enriched} {
		incident := models.Incident{
			IncidentType: "ssh_failed_login",
			UserID:       user.ID,
			CollectorID:  collector.ID,
			IPAddressID:  ip.ID,
			HappenedAt:   time.Now(),
		}
		if err := db.Create(&incident).Error; err != nil {
			t.Fatalf("seed incident: %v", err)
		}
	}

	events, err := svc.GetAttackMapEvents(user.ID, 40)
	if err != nil {
		t.Fatalf("GetAttackMapEvents: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 plottable events (no MaxMind data => every destination is unresolvable), got %d: %+v", len(events), events)
	}
}

func TestGetDashboardStats_NoIncidentsIsZeroNotError(t *testing.T) {
	db := openTestDB(t)
	svc := NewDashboardService(db, testLocationService(t, db))
	user := createTestUser(t, db)

	stats, err := svc.GetDashboardStats(user.ID)
	if err != nil {
		t.Fatalf("GetDashboardStats: %v", err)
	}
	if stats.TotalIncidents != 0 {
		t.Errorf("TotalIncidents = %d, want 0", stats.TotalIncidents)
	}
	if len(stats.HourlyIncidents) != 24 {
		t.Errorf("expected 24 hourly buckets even with no data, got %d", len(stats.HourlyIncidents))
	}
}
