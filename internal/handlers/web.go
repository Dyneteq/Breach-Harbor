package handlers

import (
	"net/http"
	"strconv"

	"github.com/Dyneteq/Breach-Harbor/internal/models"
	"github.com/Dyneteq/Breach-Harbor/internal/services"

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

// setAuthCookie sets auth_token with SameSite=Strict — every
// state-changing /api/web route (including the local-agent
// start/stop/enforce endpoints in internal/server) authenticates via
// this cookie (middleware.bearerToken's header-then-cookie fallback),
// and none of them carry a separate CSRF token. SameSite=Strict is
// what actually closes that gap: the browser won't attach this cookie
// to any cross-site request, so a page on another origin can't ride a
// logged-in user's session to (for example) flip the local agent into
// enforcing. Kept as one helper rather than repeating the flag at each
// call site so it can't quietly drift back to the default.
func setAuthCookie(c *gin.Context, token string) {
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie("auth_token", token, 3600*24, "/", "", false, true) // 24 hours
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

func (h *WebHandler) ProfilePage(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.Redirect(http.StatusTemporaryRedirect, "/login")
		return
	}

	user, err := h.authService.GetUserByID(userID.(uint))
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"error": "Account not found",
		})
		return
	}

	c.HTML(http.StatusOK, "profile.html", gin.H{
		"title": "Profile - BREACH::HARBOR",
		"user":  user,
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
		"collectors": withStatus(collectors),
	})
}

// CollectorsListFragment is what collectors_list.html's own
// hx-trigger="load delay:5s, every 5s" polls (GET /api/web/collectors)
// to keep Online/Error/Enrolled status live without a page reload —
// same self-polling pattern as the Local Agent panel
// (internal/server/localagent_handlers.go's renderLocalAgentPanel).
// Renders just the list fragment, not the full page.
func (h *WebHandler) CollectorsListFragment(c *gin.Context) {
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

	c.HTML(http.StatusOK, "collectors_list.html", gin.H{
		"collectors": withStatus(collectors),
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

// CollectorIncidentsPage backs collectors.html's card click-through
// (window.location = '/collectors/{name}/incidents') — previously
// unrouted, so it fell through to gin's JSON 404 instead of a page.
func (h *WebHandler) CollectorIncidentsPage(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.Redirect(http.StatusTemporaryRedirect, "/login")
		return
	}

	name := c.Param("name")
	collector, err := h.collectorService.GetCollectorByName(userID.(uint), name)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"error": "Collector not found",
		})
		return
	}

	incidents, err := h.collectorService.GetIncidentsByCollectorName(userID.(uint), name)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Failed to load incidents",
		})
		return
	}

	c.HTML(http.StatusOK, "incidents.html", gin.H{
		"title":     collector.Name + " Incidents - BREACH::HARBOR",
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
	setAuthCookie(c, token)

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
	setAuthCookie(c, token)

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
			"title":      "Collectors - BREACH::HARBOR",
			"collectors": withStatus(h.currentCollectorsOrEmpty(userID.(uint))),
			"error":      "Name and IP address are required",
		})
		return
	}

	collector, token, err := h.collectorService.CreateCollector(userID.(uint), name, ip)
	if err != nil {
		c.HTML(http.StatusBadRequest, "collectors.html", gin.H{
			"title":      "Collectors - BREACH::HARBOR",
			"collectors": withStatus(h.currentCollectorsOrEmpty(userID.(uint))),
			"error":      "Failed to create collector. Name may already be in use.",
		})
		return
	}

	// The plaintext token is only ever available right here, at
	// creation (the database only stores its hash) — render it inline
	// instead of the old HX-Redirect, which would have discarded it.
	c.HTML(http.StatusOK, "collectors.html", gin.H{
		"title":            "Collectors - BREACH::HARBOR",
		"collectors":       withStatus(h.currentCollectorsOrEmpty(userID.(uint))),
		"success":          "Collector created successfully! Copy its token now — it won't be shown again.",
		"newToken":         token,
		"newCollectorName": collector.Name,
	})
}

// currentCollectorsOrEmpty is HandleCreateCollector's shared fallback
// across all three of its response paths (validation error, create
// error, success) — an empty slice rather than a failed reload
// keeping the page from rendering at all.
func (h *WebHandler) currentCollectorsOrEmpty(userID uint) []models.Collector {
	collectors, err := h.collectorService.GetCollectorsByUserID(userID)
	if err != nil {
		return []models.Collector{}
	}
	return collectors
}

func (h *WebHandler) HandleDeleteCollector(c *gin.Context) {
	userID, _ := c.Get("user_id")
	collectorName := c.Param("name")

	if err := h.collectorService.DeleteCollector(userID.(uint), collectorName); err != nil {
		c.String(http.StatusNotFound, "")
		return
	}

	// The delete button targets this card with hx-swap="outerHTML" —
	// an empty 200 response removes it from the page.
	c.Status(http.StatusOK)
}
