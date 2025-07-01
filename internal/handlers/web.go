package handlers

import (
	"net/http"
	"strconv"

	"breach-harbor-core/internal/models"
	"breach-harbor-core/internal/services"

	"github.com/gin-gonic/gin"
)

type WebHandler struct {
	authService      *services.AuthService
	collectorService *services.CollectorService
	dashboardService *services.DashboardService
}

func NewWebHandler(authService *services.AuthService, collectorService *services.CollectorService, dashboardService *services.DashboardService) *WebHandler {
	return &WebHandler{
		authService:      authService,
		collectorService: collectorService,
		dashboardService: dashboardService,
	}
}

func (h *WebHandler) LoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{
		"title": "Login - BREACH::HARBOR",
	})
}

func (h *WebHandler) RegisterPage(c *gin.Context) {
	c.HTML(http.StatusOK, "register.html", gin.H{
		"title": "Register - BREACH::HARBOR",
	})
}

func (h *WebHandler) DashboardPage(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.Redirect(http.StatusTemporaryRedirect, "/login")
		return
	}

	stats, err := h.dashboardService.GetDashboardStats(userID.(uint))
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Failed to load dashboard",
		})
		return
	}

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"title": "Dashboard - BREACH::HARBOR",
		"stats": stats,
	})
}

func (h *WebHandler) CollectorsPage(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.Redirect(http.StatusTemporaryRedirect, "/login")
		return
	}

	collectors, err := h.collectorService.GetCollectorsByUserID(userID.(uint))
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Failed to load collectors",
		})
		return
	}

	c.HTML(http.StatusOK, "collectors.html", gin.H{
		"title":      "Collectors - BREACH::HARBOR",
		"collectors": collectors,
	})
}

func (h *WebHandler) IncidentsPage(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.Redirect(http.StatusTemporaryRedirect, "/login")
		return
	}

	incidents, err := h.collectorService.GetIncidentsByUserID(userID.(uint))
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Failed to load incidents",
		})
		return
	}

	c.HTML(http.StatusOK, "incidents.html", gin.H{
		"title":     "Incidents - BREACH::HARBOR",
		"incidents": incidents,
	})
}

func (h *WebHandler) IncidentDetailsPage(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.Redirect(http.StatusTemporaryRedirect, "/login")
		return
	}

	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Invalid incident ID",
		})
		return
	}

	incident, err := h.collectorService.GetIncidentByID(userID.(uint), uint(id))
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"error": "Incident not found",
		})
		return
	}

	c.HTML(http.StatusOK, "incident_details.html", gin.H{
		"title":    "Incident Details - BREACH::HARBOR",
		"incident": incident,
	})
}

func (h *WebHandler) IPAddressesPage(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.Redirect(http.StatusTemporaryRedirect, "/login")
		return
	}

	ipAddresses, err := h.dashboardService.GetAllIPAddresses(userID.(uint))
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Failed to load IP addresses",
		})
		return
	}

	c.HTML(http.StatusOK, "ip_addresses.html", gin.H{
		"title":        "IP Addresses - BREACH::HARBOR",
		"ip_addresses": ipAddresses,
	})
}

func (h *WebHandler) IPAddressDetailsPage(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.Redirect(http.StatusTemporaryRedirect, "/login")
		return
	}

	ip := c.Param("ip")
	ipAddress, incidents, err := h.dashboardService.GetIPAddressDetails(userID.(uint), ip)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"error": "IP address not found",
		})
		return
	}

	c.HTML(http.StatusOK, "ip_address_details.html", gin.H{
		"title":      "IP Address Details - BREACH::HARBOR",
		"ip_address": ipAddress,
		"incidents":  incidents,
	})
}

func (h *WebHandler) HandleLogin(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")

	if email == "" || password == "" {
		c.HTML(http.StatusBadRequest, "login.html", gin.H{
			"title": "Login - BREACH::HARBOR",
			"error": "Email and password are required",
		})
		return
	}

	user, token, err := h.authService.Login(email, password)
	if err != nil {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"title": "Login - BREACH::HARBOR",
			"error": "Invalid email or password",
		})
		return
	}

	// Set authentication cookie
	c.SetCookie("auth_token", token, 3600*24, "/", "", false, true) // 24 hours

	// Redirect to dashboard
	c.Header("HX-Redirect", "/dashboard")
	c.Status(http.StatusOK)
	
	_ = user // Use the user variable to avoid compiler warning
}

func (h *WebHandler) HandleRegister(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")
	firstName := c.PostForm("first_name")
	lastName := c.PostForm("last_name")
	confirmPassword := c.PostForm("confirm_password")

	if email == "" || password == "" || firstName == "" || lastName == "" {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"title": "Register - BREACH::HARBOR",
			"error": "All fields are required",
		})
		return
	}

	if password != confirmPassword {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"title": "Register - BREACH::HARBOR",
			"error": "Passwords do not match",
		})
		return
	}

	if len(password) < 8 {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"title": "Register - BREACH::HARBOR",
			"error": "Password must be at least 8 characters long",
		})
		return
	}

	user, err := h.authService.Register(email, password, firstName, lastName)
	if err != nil {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"title": "Register - BREACH::HARBOR",
			"error": "Failed to create account. Email may already be in use.",
		})
		return
	}

	// Generate token for automatic login
	token, err := h.authService.GenerateJWT(user)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{
			"title": "Register - BREACH::HARBOR",
			"error": "Account created but failed to login. Please try logging in.",
		})
		return
	}

	// Set authentication cookie
	c.SetCookie("auth_token", token, 3600*24, "/", "", false, true) // 24 hours

	// Redirect to dashboard
	c.Header("HX-Redirect", "/dashboard")
	c.Status(http.StatusOK)
}

func (h *WebHandler) HandleLogout(c *gin.Context) {
	// Clear authentication cookie
	c.SetCookie("auth_token", "", -1, "/", "", false, true)
	
	// Redirect to login
	c.Header("HX-Redirect", "/login")
	c.Status(http.StatusOK)
}

func (h *WebHandler) HandleCreateCollector(c *gin.Context) {
	userID, _ := c.Get("user_id")
	
	name := c.PostForm("name")
	ip := c.PostForm("ip")

	if name == "" || ip == "" {
		c.HTML(http.StatusBadRequest, "collectors.html", gin.H{
			"title": "Collectors - BREACH::HARBOR",
			"error": "Name and IP address are required",
		})
		return
	}

	collector, err := h.collectorService.CreateCollector(userID.(uint), name, ip)
	if err != nil {
		c.HTML(http.StatusBadRequest, "collectors.html", gin.H{
			"title": "Collectors - BREACH::HARBOR",
			"error": "Failed to create collector. Name may already be in use.",
		})
		return
	}

	// Get updated collectors list
	collectors, err := h.collectorService.GetCollectorsByUserID(userID.(uint))
	if err != nil {
		collectors = []models.Collector{}
	}

	// Return success and redirect
	c.Header("HX-Redirect", "/collectors")
	c.HTML(http.StatusOK, "collectors.html", gin.H{
		"title":      "Collectors - BREACH::HARBOR",
		"collectors": collectors,
		"success":    "Collector created successfully!",
	})
	
	_ = collector // Use the collector variable to avoid compiler warning
}

func (h *WebHandler) HandleDeleteCollector(c *gin.Context) {
	userID, _ := c.Get("user_id")
	collectorName := c.Param("name")

	// Here you would implement the delete logic
	// For now, just redirect back to collectors page
	c.Header("HX-Redirect", "/collectors")
	c.Status(http.StatusOK)
	
	_ = userID        // Use variables to avoid compiler warnings
	_ = collectorName
}