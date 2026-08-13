package handlers

import (
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/models"
)

// IncidentRow is one displayable row on the incidents page: either a
// single incident, or a run of consecutive incidents (same type, same
// source IP, same collector, back-to-back in time-descending order)
// collapsed into one row so a repeated scan or brute-force burst
// doesn't drown the list in near-duplicate lines.
type IncidentRow struct {
	models.Incident
	// Count is how many incidents this row represents (1 for an
	// ungrouped incident).
	Count int
	// FirstAt/LastAt are the earliest/latest CreatedAt in the group;
	// equal to the embedded Incident's CreatedAt when Count is 1.
	FirstAt time.Time
	LastAt  time.Time
}

// groupConsequentIncidents collapses runs of consecutive incidents
// sharing the same type, source IP, and collector into single rows.
// "Consequent" means adjacent in incidents' existing order (callers
// pass created_at DESC) — a matching incident separated by a
// different one in between starts a new group rather than merging
// into an earlier one, since it's the intervening group that made a
// glance-worthy difference on the page.
func groupConsequentIncidents(incidents []models.Incident) []IncidentRow {
	rows := make([]IncidentRow, 0, len(incidents))
	for _, inc := range incidents {
		if n := len(rows); n > 0 {
			last := &rows[n-1]
			if last.IncidentType == inc.IncidentType &&
				last.IPAddressID == inc.IPAddressID &&
				last.CollectorID == inc.CollectorID {
				last.Count++
				if inc.CreatedAt.Before(last.FirstAt) {
					last.FirstAt = inc.CreatedAt
				}
				if inc.CreatedAt.After(last.LastAt) {
					last.LastAt = inc.CreatedAt
				}
				continue
			}
		}
		rows = append(rows, IncidentRow{
			Incident: inc,
			Count:    1,
			FirstAt:  inc.CreatedAt,
			LastAt:   inc.CreatedAt,
		})
	}
	return rows
}
