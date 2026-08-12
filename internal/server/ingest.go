package server

import (
	"net/http"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/services"

	"github.com/gin-gonic/gin"
)

// observationRequest is one event in a POST /v1/observations batch —
// the wire shape an enrolled agent's uploader.go sends.
type observationRequest struct {
	IP           string                 `json:"ip" binding:"required,ip"`
	IncidentType string                 `json:"incident_type" binding:"required"`
	HappenedAt   time.Time              `json:"happened_at"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type observationsRequest struct {
	Observations []observationRequest `json:"observations" binding:"required,min=1,dive"`
}

// handleObservations replaces the old one-event-per-request path
// (handlers/collector.go's CreateIncident, still mounted at
// POST /v1/incidents for parity) with a single batched insert
// (PLAN.md M2 item 1/3: CreateInBatches instead of one row at a time).
func (s *Server) handleObservations(c *gin.Context) {
	token, _ := c.Get("collector_token")

	var req observationsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	inputs := make([]services.ObservationInput, 0, len(req.Observations))
	for _, o := range req.Observations {
		inputs = append(inputs, services.ObservationInput{
			IP:           o.IP,
			IncidentType: o.IncidentType,
			HappenedAt:   o.HappenedAt,
			Metadata:     o.Metadata,
		})
	}

	incidents, err := s.collectorService.CreateIncidentsBatch(token.(string), inputs)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"ingested": len(incidents)})
}

// firewallStatusRequest is POST /v1/firewall-status's body — the wire
// shape internal/agent/uploader.go's SendFirewallStatus sends.
type firewallStatusRequest struct {
	Backend    string   `json:"backend" binding:"required"`
	Enforcing  bool     `json:"enforcing"`
	BlockedIPs []string `json:"blocked_ips"`
}

// handleFirewallStatus is POST /v1/firewall-status: an enrolled agent
// calls this on its own heartbeat-adjacent ticker (internal/agent's
// sendFirewallStatus) to report what its firewall.Backend currently
// has in effect. Like /v1/heartbeat this is a point-in-time snapshot,
// not queued data — a failed report just means the dashboard shows
// stale firewall info until the next tick succeeds.
func (s *Server) handleFirewallStatus(c *gin.Context) {
	collectorID, _ := c.Get("collector_id")

	var req firewallStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.collectorService.RecordFirewallStatus(collectorID.(uint), req.Backend, req.Enforcing, req.BlockedIPs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record firewall status"})
		return
	}
	c.Status(http.StatusNoContent)
}

// handleGetBlocklist serves the most recently published signed
// blocklist. 503 (not 404) while the very first publish is still in
// flight — this is a transient startup state, not a permanent absence.
func (s *Server) handleGetBlocklist(c *gin.Context) {
	current, ok := s.publisher.Current()
	if !ok {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "blocklist not published yet, try again shortly"})
		return
	}
	c.JSON(http.StatusOK, current)
}
