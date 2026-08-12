package handlers

import (
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/models"
)

// heartbeatOnlineWindow is how stale a collector's LastHeartbeat can
// be before it flips from "online" to "error" on the dashboard —
// three times internal/agent's heartbeatInterval (60s), giving room
// for a couple of missed/delayed beats before treating an agent as
// down. Kept in sync with that constant by hand: see its own doc
// comment (internal/agent/agent.go) on why these live in separate
// packages rather than importing one into the other for one constant.
const heartbeatOnlineWindow = 3 * time.Minute

// collectorView augments models.Collector with a derived Status for
// the dashboard's badge — presentation-only. Not exposed via the JSON
// API (internal/handlers/collector.go), which returns the raw
// EnrolledAt/LastOnline/LastHeartbeat fields and lets API consumers
// derive their own status if they want one.
type collectorView struct {
	models.Collector
	Status string // "never_connected", "enrolled", "online", "error"
}

// collectorStatus derives the dashboard's four-state badge from a
// collector's two independent presence signals:
//   - LastHeartbeat: the agent process is alive and can reach the
//     server right now, regardless of whether it's detected anything
//     (POST /v1/heartbeat, internal/agent's sendHeartbeat).
//   - EnrolledAt: the collector's token has been used successfully at
//     least once, but no heartbeat has ever landed (agent enrolled but
//     never run, or an old build predating the heartbeat feature).
//
// A collector can have real incident history (LastOnline) yet still
// be offline right now — that's shown separately in the template, not
// folded into this status.
func collectorStatus(c models.Collector, now time.Time) string {
	if c.LastHeartbeat != nil {
		if now.Sub(*c.LastHeartbeat) <= heartbeatOnlineWindow {
			return "online"
		}
		return "error"
	}
	if c.EnrolledAt != nil {
		return "enrolled"
	}
	return "never_connected"
}

// withStatus wraps each collector with its derived Status, in order —
// the view-model shape every dashboard collectors handler renders.
func withStatus(collectors []models.Collector) []collectorView {
	now := time.Now()
	views := make([]collectorView, len(collectors))
	for i, c := range collectors {
		views[i] = collectorView{Collector: c, Status: collectorStatus(c, now)}
	}
	return views
}
