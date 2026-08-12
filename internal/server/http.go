package server

import (
	"html/template"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/Dyneteq/Breach-Harbor/internal/handlers"
	"github.com/Dyneteq/Breach-Harbor/internal/middleware"

	"github.com/gin-gonic/gin"
)

// buildRouter registers every route this project has ever documented
// but never wired up: the JSON REST API (/api/v1), the HTMX form
// endpoints behind the server-rendered dashboard (/api/web), the
// dashboard pages themselves (gated by Config.Web), and the
// agent-facing surface (/v1/enroll, /v1/observations, /v1/blocklist).
func (s *Server) buildRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/health", s.handleHealth)

	authHandler := handlers.NewAuthHandler(s.authService)
	collectorHandler := handlers.NewCollectorHandler(s.collectorService)
	dashboardHandler := handlers.NewDashboardHandler(s.dashboardService)

	api := r.Group("/api")
	{
		api.POST("/auth/login", authHandler.Login)
		api.POST("/auth/register", authHandler.Register)

		v1 := api.Group("/v1")
		v1.Use(middleware.AuthMiddleware(s.authService))
		{
			v1.GET("/auth/me", authHandler.GetCurrentUser)

			v1.GET("/collectors", collectorHandler.GetCollectors)
			v1.POST("/collectors", collectorHandler.CreateCollector)
			v1.GET("/collectors/:name", collectorHandler.GetCollectorByName)
			v1.GET("/collectors/:name/incidents", collectorHandler.GetIncidentsByCollector)

			v1.GET("/incidents", collectorHandler.GetIncidents)
			v1.GET("/incidents/:id", collectorHandler.GetIncidentByID)

			v1.GET("/dashboard", dashboardHandler.GetStats)
			v1.GET("/dashboard/attack-map", dashboardHandler.GetAttackMap)
			v1.GET("/ip-addresses", dashboardHandler.GetIPAddresses)
			v1.GET("/ip-addresses/:ip", dashboardHandler.GetIPAddressDetails)
			v1.GET("/ip-addresses/:ip/attack-map", dashboardHandler.GetIPAttackMap)
		}
	}

	// Agent-facing surface (PLAN.md M2 item 1): collector-bearer-token
	// auth, not user JWT auth — an enrolled agent has no user session.
	agentV1 := r.Group("/v1")
	agentV1.Use(middleware.CollectorAuthMiddleware(s.collectorService))
	{
		agentV1.POST("/enroll", s.handleEnroll)
		agentV1.POST("/heartbeat", s.handleHeartbeat)
		agentV1.POST("/firewall-status", s.handleFirewallStatus)
		agentV1.POST("/observations", s.handleObservations)
		agentV1.GET("/blocklist", s.handleGetBlocklist)
	}
	// Ingest also accepts one-observation-at-a-time for parity with
	// the old CollectorHandler.CreateIncident shape — the batched
	// /v1/observations above is the path an enrolled agent actually
	// uses (internal/agent/uploader.go).
	r.POST("/v1/incidents", middleware.CollectorAuthMiddleware(s.collectorService), collectorHandler.CreateIncident)

	if s.cfg.Web {
		s.registerWebRoutes(r)
	}

	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	})

	return r
}

// registerWebRoutes wires the server-rendered dashboard (templates/ +
// static/, HTMX forms) — the "existing dashboard" PLAN.md's M2 section
// scoped this milestone to wire up, not redesign.
func (s *Server) registerWebRoutes(r *gin.Engine) {
	// "lower" is used by five templates (ip_addresses.html,
	// incident_details.html, dashboard.html, incidents.html,
	// ip_address_details.html) to build a flag-icon CSS class from a
	// country code — {{.CountryCode | lower}} — but isn't one of
	// html/template's builtin functions. This was never caught before
	// M2 because this is the first time anything actually called
	// LoadHTMLGlob; SetFuncMap must run before it or gin's
	// template.Must(...) panics at startup.
	r.SetFuncMap(template.FuncMap{"lower": strings.ToLower})
	r.LoadHTMLGlob(filepath.Join(s.cfg.TemplatesDir, "*.html"))
	r.Static("/static", s.cfg.StaticDir)

	webHandler := handlers.NewWebHandler(s.authService, s.collectorService, s.dashboardService)

	r.GET("/", func(c *gin.Context) { c.Redirect(http.StatusFound, "/login") })
	r.GET("/login", webHandler.LoginPage)
	r.GET("/register", webHandler.RegisterPage)

	webAPI := r.Group("/api/web")
	{
		webAPI.POST("/login", webHandler.HandleLogin)
		webAPI.POST("/register", webHandler.HandleRegister)
		webAPI.POST("/logout", webHandler.HandleLogout)

		webAuthed := webAPI.Group("")
		webAuthed.Use(middleware.WebAuthMiddleware(s.authService))
		{
			webAuthed.GET("/collectors", webHandler.CollectorsListFragment)
			webAuthed.POST("/collectors", webHandler.HandleCreateCollector)
			webAuthed.DELETE("/collectors/:name", webHandler.HandleDeleteCollector)

			webAuthed.GET("/local-agent", s.handleLocalAgentStatus)
			webAuthed.POST("/local-agent/start", s.handleLocalAgentStart)
			webAuthed.POST("/local-agent/stop", s.handleLocalAgentStop)
			webAuthed.POST("/local-agent/enforce", s.handleLocalAgentEnforce)
		}
	}

	pages := r.Group("")
	pages.Use(middleware.WebAuthMiddleware(s.authService))
	{
		pages.GET("/dashboard", webHandler.DashboardPage)
		pages.GET("/profile", webHandler.ProfilePage)
		pages.GET("/collectors", webHandler.CollectorsPage)
		pages.GET("/collectors/:name/incidents", webHandler.CollectorIncidentsPage)
		pages.GET("/incidents", webHandler.IncidentsPage)
		pages.GET("/incidents/:id", webHandler.IncidentDetailsPage)
		pages.GET("/ip-addresses", webHandler.IPAddressesPage)
		pages.GET("/ip-addresses/:ip", webHandler.IPAddressDetailsPage)
	}
}

func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
