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
	svc := NewDashboardService(db)
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

func TestGetDashboardStats_NoIncidentsIsZeroNotError(t *testing.T) {
	db := openTestDB(t)
	svc := NewDashboardService(db)
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
