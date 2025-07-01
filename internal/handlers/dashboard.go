package handlers

import (
	"net/http"

	"breach-harbor-core/internal/services"

	"github.com/gin-gonic/gin"
)

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