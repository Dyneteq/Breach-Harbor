package handlers

import (
	"net/http"
	"strconv"

	"breach-harbor-core/internal/services"

	"github.com/gin-gonic/gin"
)

type CollectorHandler struct {
	collectorService *services.CollectorService
}

type CreateCollectorRequest struct {
	Name string `json:"name" binding:"required"`
	IP   string `json:"ip" binding:"required,ip"`
}

type CreateIncidentRequest struct {
	IP           string                 `json:"ip" binding:"required,ip"`
	IncidentType string                 `json:"incident_type" binding:"required"`
	Metadata     map[string]interface{} `json:"metadata"`
}

func NewCollectorHandler(collectorService *services.CollectorService) *CollectorHandler {
	return &CollectorHandler{collectorService: collectorService}
}

func (h *CollectorHandler) GetCollectors(c *gin.Context) {
	userID, _ := c.Get("user_id")
	
	collectors, err := h.collectorService.GetCollectorsByUserID(userID.(uint))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get collectors"})
		return
	}

	c.JSON(http.StatusOK, collectors)
}

func (h *CollectorHandler) CreateCollector(c *gin.Context) {
	userID, _ := c.Get("user_id")
	
	var req CreateCollectorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	collector, err := h.collectorService.CreateCollector(userID.(uint), req.Name, req.IP)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create collector"})
		return
	}

	c.JSON(http.StatusCreated, collector)
}

func (h *CollectorHandler) GetCollectorByName(c *gin.Context) {
	userID, _ := c.Get("user_id")
	name := c.Param("name")

	collector, err := h.collectorService.GetCollectorByName(userID.(uint), name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Collector not found"})
		return
	}

	c.JSON(http.StatusOK, collector)
}

func (h *CollectorHandler) CreateIncident(c *gin.Context) {
	collectorToken, _ := c.Get("collector_token")
	
	var req CreateIncidentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	incident, err := h.collectorService.CreateIncident(
		collectorToken.(string),
		req.IP,
		req.IncidentType,
		req.Metadata,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, incident)
}

func (h *CollectorHandler) GetIncidents(c *gin.Context) {
	userID, _ := c.Get("user_id")
	
	incidents, err := h.collectorService.GetIncidentsByUserID(userID.(uint))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get incidents"})
		return
	}

	c.JSON(http.StatusOK, incidents)
}

func (h *CollectorHandler) GetIncidentByID(c *gin.Context) {
	userID, _ := c.Get("user_id")
	idStr := c.Param("id")
	
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid incident ID"})
		return
	}

	incident, err := h.collectorService.GetIncidentByID(userID.(uint), uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Incident not found"})
		return
	}

	c.JSON(http.StatusOK, incident)
}

func (h *CollectorHandler) GetIncidentsByCollector(c *gin.Context) {
	userID, _ := c.Get("user_id")
	collectorName := c.Param("name")
	
	incidents, err := h.collectorService.GetIncidentsByCollectorName(userID.(uint), collectorName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get incidents"})
		return
	}

	c.JSON(http.StatusOK, incidents)
}