package server

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// enrollResponse is what a freshly-enrolling agent needs to start
// operating: confirmation of which collector its token maps to, and
// the server's blocklist-signing public key to pin (bare TOFU — see
// PLAN.md's M3 sketch for pinning/rotation hardening beyond this).
type enrollResponse struct {
	CollectorName string `json:"collector_name"`
	CollectorIP   string `json:"collector_ip"`
	PublicKey     []byte `json:"public_key"`
}

// handleEnroll is POST /v1/enroll: the collector token has already
// been validated by CollectorAuthMiddleware by the time this runs, so
// this just looks up which collector it belongs to and hands back the
// signing key — internal/agent/enroll.go persists both locally.
func (s *Server) handleEnroll(c *gin.Context) {
	collectorID, _ := c.Get("collector_id")

	collector, err := s.collectorService.GetCollectorByID(collectorID.(uint))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "collector not found"})
		return
	}

	// Best-effort: the agent's enrollment response below doesn't
	// depend on this write succeeding, so a DB hiccup here logs
	// rather than failing an otherwise-successful enroll.
	if err := s.collectorService.MarkEnrolled(collector.ID); err != nil {
		log.Printf("mark collector %d enrolled: %v", collector.ID, err)
	}

	c.JSON(http.StatusOK, enrollResponse{
		CollectorName: collector.Name,
		CollectorIP:   collector.IP,
		PublicKey:     s.signer.PublicKey(),
	})
}

// handleHeartbeat is POST /v1/heartbeat: an enrolled agent calls this
// on its own fixed ticker (internal/agent's heartbeatInterval)
// whether or not it has anything to report — the presence signal
// behind the dashboard's Online/Error status, independent of
// UpdateLastOnline (which only moves when real data flows, via
// /v1/observations). No request body: the bearer token alone, already
// validated by CollectorAuthMiddleware, is the entire payload.
func (s *Server) handleHeartbeat(c *gin.Context) {
	collectorID, _ := c.Get("collector_id")
	if err := s.collectorService.RecordHeartbeat(collectorID.(uint)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record heartbeat"})
		return
	}
	c.Status(http.StatusNoContent)
}
