package handlers

import (
	"testing"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/models"
)

func TestCollectorStatus(t *testing.T) {
	now := time.Now()
	recent := now.Add(-1 * time.Minute)
	stale := now.Add(-10 * time.Minute) // well past heartbeatOnlineWindow (3m)
	enrolledAt := now.Add(-1 * time.Hour)

	cases := []struct {
		name string
		c    models.Collector
		want string
	}{
		{"never enrolled, no heartbeat", models.Collector{}, "never_connected"},
		{"enrolled, never heartbeated", models.Collector{EnrolledAt: &enrolledAt}, "enrolled"},
		{"recent heartbeat", models.Collector{EnrolledAt: &enrolledAt, LastHeartbeat: &recent}, "online"},
		{"stale heartbeat", models.Collector{EnrolledAt: &enrolledAt, LastHeartbeat: &stale}, "error"},
		{
			"heartbeat present but never enrolled (shouldn't happen in practice, but heartbeat wins)",
			models.Collector{LastHeartbeat: &recent},
			"online",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := collectorStatus(tc.c, now); got != tc.want {
				t.Errorf("collectorStatus() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCollectorStatus_ExactlyAtWindowBoundary(t *testing.T) {
	now := time.Now()
	boundary := now.Add(-heartbeatOnlineWindow)
	c := models.Collector{LastHeartbeat: &boundary}
	if got := collectorStatus(c, now); got != "online" {
		t.Errorf("collectorStatus() at exactly the window boundary = %q, want %q (inclusive)", got, "online")
	}

	justPast := now.Add(-heartbeatOnlineWindow - time.Second)
	c2 := models.Collector{LastHeartbeat: &justPast}
	if got := collectorStatus(c2, now); got != "error" {
		t.Errorf("collectorStatus() just past the window boundary = %q, want %q", got, "error")
	}
}

func TestWithStatus_PreservesOrderAndFields(t *testing.T) {
	now := time.Now()
	collectors := []models.Collector{
		{Name: "a", LastHeartbeat: &now},
		{Name: "b"},
	}

	views := withStatus(collectors)
	if len(views) != 2 {
		t.Fatalf("len(views) = %d, want 2", len(views))
	}
	if views[0].Name != "a" || views[0].Status != "online" {
		t.Errorf("views[0] = %+v, want Name=a Status=online", views[0])
	}
	if views[1].Name != "b" || views[1].Status != "never_connected" {
		t.Errorf("views[1] = %+v, want Name=b Status=never_connected", views[1])
	}
}
