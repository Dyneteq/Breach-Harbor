package handlers

import (
	"net/http"
	"strconv"

	"github.com/Dyneteq/Breach-Harbor/internal/services"

	"github.com/gin-gonic/gin"
)

// attackMapLimit parses and clamps the optional ?limit= query param shared
// by both attack-map endpoints, defaulting to 40 recent incidents.
func attackMapLimit(c *gin.Context) int {
	limit := 40
	if v, err := strconv.Atoi(c.Query("limit")); err == nil {
		limit = v
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}
	return limit
}

type DashboardHandler struct {
	dashboardService *services.DashboardService
}

func NewDashboardHandler(dashboardService *services.DashboardService) *DashboardHandler {
	return &DashboardHandler{dashboardService: dashboardService}
}

func (h *DashboardHandler) GetStats(c *gin.Context) {
	userID, _ := c.Get("user_id")

	stats, err := h.dashboardService.GetDashboardStats(userID.(uint))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get dashboard stats"})
		return
	}

	c.JSON(http.StatusOK, stats)
}

func (h *DashboardHandler) GetIPAddresses(c *gin.Context) {
	userID, _ := c.Get("user_id")

	ipAddresses, err := h.dashboardService.GetAllIPAddresses(userID.(uint))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get IP addresses"})
		return
	}

	c.JSON(http.StatusOK, ipAddresses)
}

// GetAttackMap backs the dashboard's animated attack map: recent incidents
// across every collector, shaped as source/destination coordinate pairs.
func (h *DashboardHandler) GetAttackMap(c *gin.Context) {
	userID, _ := c.Get("user_id")

	events, err := h.dashboardService.GetAttackMapEvents(userID.(uint), attackMapLimit(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get attack map events"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"events": events})
}

// GetIPAttackMap backs the IP address detail page's attack map: this one
// IP's incidents, as arcs to whichever collector(s) observed it.
func (h *DashboardHandler) GetIPAttackMap(c *gin.Context) {
	userID, _ := c.Get("user_id")
	ip := c.Param("ip")

	events, err := h.dashboardService.GetIPAttackMapEvents(userID.(uint), ip, attackMapLimit(c))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "IP address not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"events": events})
}

func (h *DashboardHandler) GetIPAddressDetails(c *gin.Context) {
	userID, _ := c.Get("user_id")
	ip := c.Param("ip")

	ipAddress, incidents, err := h.dashboardService.GetIPAddressDetails(userID.(uint), ip)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "IP address not found"})
		return
	}

	response := map[string]interface{}{
		"ip_address": ipAddress,
		"incidents":  incidents,
	}

	c.JSON(http.StatusOK, response)
}
