package server

import (
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

	c.JSON(http.StatusOK, enrollResponse{
		CollectorName: collector.Name,
		CollectorIP:   collector.IP,
		PublicKey:     s.signer.PublicKey(),
	})
}
