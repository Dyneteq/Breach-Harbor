package handlers

import (
	"testing"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/models"
)

func TestGroupConsequentIncidents(t *testing.T) {
	t0 := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	inc := func(offset time.Duration, incidentType string, ip, collector uint) models.Incident {
		return models.Incident{
			IncidentType: incidentType,
			IPAddressID:  ip,
			CollectorID:  collector,
			CreatedAt:    t0.Add(offset),
		}
	}

	t.Run("collapses a consecutive run into one row", func(t *testing.T) {
		incidents := []models.Incident{
			inc(2*time.Minute, "port_scan", 1, 1),
			inc(1*time.Minute, "port_scan", 1, 1),
			inc(0, "port_scan", 1, 1),
		}

		rows := groupConsequentIncidents(incidents)
		if len(rows) != 1 {
			t.Fatalf("got %d rows, want 1", len(rows))
		}
		row := rows[0]
		if row.Count != 3 {
			t.Errorf("Count = %d, want 3", row.Count)
		}
		if !row.CreatedAt.Equal(t0.Add(2 * time.Minute)) {
			t.Errorf("row CreatedAt = %v, want the most recent incident's", row.CreatedAt)
		}
		if !row.FirstAt.Equal(t0) {
			t.Errorf("FirstAt = %v, want %v", row.FirstAt, t0)
		}
		if !row.LastAt.Equal(t0.Add(2 * time.Minute)) {
			t.Errorf("LastAt = %v, want %v", row.LastAt, t0.Add(2*time.Minute))
		}
	})

	t.Run("does not merge across a different intervening incident", func(t *testing.T) {
		incidents := []models.Incident{
			inc(2*time.Minute, "port_scan", 1, 1),
			inc(1*time.Minute, "brute_force", 1, 1),
			inc(0, "port_scan", 1, 1),
		}

		rows := groupConsequentIncidents(incidents)
		if len(rows) != 3 {
			t.Fatalf("got %d rows, want 3 (no merge across a different type)", len(rows))
		}
		for _, row := range rows {
			if row.Count != 1 {
				t.Errorf("Count = %d, want 1 for an ungrouped row", row.Count)
			}
		}
	})

	t.Run("keeps distinct source IPs and collectors separate", func(t *testing.T) {
		incidents := []models.Incident{
			inc(2*time.Minute, "port_scan", 1, 1),
			inc(1*time.Minute, "port_scan", 2, 1),
			inc(0, "port_scan", 2, 2),
		}

		rows := groupConsequentIncidents(incidents)
		if len(rows) != 3 {
			t.Fatalf("got %d rows, want 3 (different IP/collector each time)", len(rows))
		}
	})

	t.Run("empty input", func(t *testing.T) {
		rows := groupConsequentIncidents(nil)
		if len(rows) != 0 {
			t.Errorf("got %d rows, want 0", len(rows))
		}
	})
}
