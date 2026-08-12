// Package server is the missing HTTP bootstrap: it wires
// internal/models/services/handlers/middleware — all of which existed
// before this project started but were never assembled into a running
// process — into one gin.Engine, plus the agent-facing surface that
// didn't exist at all (POST /v1/enroll, POST /v1/observations, GET
// /v1/blocklist) and the ticker that signs and republishes the
// blocklist on a schedule.
package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/blocklist"
	"github.com/Dyneteq/Breach-Harbor/internal/config"
	"github.com/Dyneteq/Breach-Harbor/internal/feed"
	"github.com/Dyneteq/Breach-Harbor/internal/models"
	"github.com/Dyneteq/Breach-Harbor/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// Config is the server's own configuration — analogous to
// internal/agent.Config: a plain struct internal/cli populates from
// flags, kept independent of any flag library.
type Config struct {
	Listen          string
	DataDir         string
	DBPath          string
	PublishInterval time.Duration
	BlocklistTTL    time.Duration
	Web             bool
	JSON            bool
	SignKeyPath     string
	// LocalAgentEnabled gates the dashboard's "start a local agent
	// against this host" feature (internal/server/localagent.go).
	// Defaults off: any self-registered user could otherwise flip it
	// into enforcing and mutate this host's own firewall — it must be
	// an explicit operator opt-in (`server run --local-agent`), not a
	// default-on surface reachable by anyone who can register.
	LocalAgentEnabled bool
	// TemplatesDir/StaticDir default to "templates"/"static", resolved
	// relative to the process's working directory — matches the
	// Dockerfile, which COPYs both next to the binary. Overridable so
	// tests (and anyone running from a different CWD) don't have to
	// chdir into the repo root.
	TemplatesDir string
	StaticDir    string
}

// DefaultConfig returns zero-flag defaults: `breachharbor server run`
// with no flags creates its SQLite DB and signing key under
// DefaultDataDir and serves the dashboard on :8080.
func DefaultConfig() Config {
	return Config{
		Listen:          ":8080",
		DataDir:         DefaultDataDir(),
		PublishInterval: 15 * time.Minute,
		BlocklistTTL:    30 * time.Minute,
		Web:             true,
		TemplatesDir:    "templates",
		StaticDir:       "static",
	}
}

// DefaultDataDir mirrors internal/agent.DefaultDataDir's root-vs-user
// split, but under a distinct name — an operator running both `agent`
// and `server` on the same box (a small, single-node deployment) must
// not have them silently share a data directory.
func DefaultDataDir() string {
	if os.Geteuid() == 0 {
		return "/var/lib/breachharbor-server"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "breachharbor-server")
	}
	return filepath.Join(home, ".local", "state", "breachharbor-server")
}

func (c Config) Validate() error {
	if c.DataDir == "" {
		return fmt.Errorf("data directory must not be empty")
	}
	if c.Listen == "" {
		return fmt.Errorf("listen address must not be empty")
	}
	if c.PublishInterval <= 0 {
		return fmt.Errorf("publish interval must be positive, got %s", c.PublishInterval)
	}
	return nil
}

// Server holds every long-lived dependency the router and background
// tickers need.
type Server struct {
	cfg    Config
	appCfg *config.Config
	db     *gorm.DB

	authService      *services.AuthService
	collectorService *services.CollectorService
	dashboardService *services.DashboardService
	locationService  *services.LocationService

	signer    *blocklist.Ed25519Signer
	publisher *blocklist.Publisher
	torFeed   *feed.CachedProvider

	localAgent *LocalAgentManager

	router *gin.Engine
}

// New opens the database, runs migrations, loads/generates the ed25519
// signing key, and builds the router. It does not start listening —
// call Run for that.
func New(cfg Config, appCfg *config.Config) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data directory %s: %w", cfg.DataDir, err)
	}

	dbPath := cfg.DBPath
	if dbPath == "" {
		dbPath = appCfg.Database.Path
	}
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		return nil, fmt.Errorf("open database %s: %w", dbPath, err)
	}
	if err := models.MigrateDatabase(db); err != nil {
		return nil, fmt.Errorf("migrate database: %w", err)
	}

	locationService, err := services.NewLocationService(db, appCfg)
	if err != nil {
		return nil, fmt.Errorf("init location service: %w", err)
	}

	signKeyPath := cfg.SignKeyPath
	if signKeyPath == "" {
		signKeyPath = filepath.Join(cfg.DataDir, "signing.key")
	}
	signer, err := blocklist.LoadOrCreateSigningKey(signKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load/create signing key: %w", err)
	}

	s := &Server{
		cfg:              cfg,
		appCfg:           appCfg,
		db:               db,
		authService:      services.NewAuthService(db, appCfg),
		collectorService: services.NewCollectorService(db, locationService),
		dashboardService: services.NewDashboardService(db, locationService),
		locationService:  locationService,
		signer:           signer,
		torFeed:          feed.NewCachedProvider(feed.NewTor(), cfg.DataDir, 15*time.Minute),
	}
	s.publisher = blocklist.NewPublisher(s.signer, s.blocklistSource, cfg.PublishInterval, cfg.BlocklistTTL)
	s.localAgent = NewLocalAgentManager(cfg.DataDir, s.collectorService, cfg.LocalAgentEnabled)
	s.router = s.buildRouter()
	return s, nil
}

func (s *Server) DB() *gorm.DB { return s.db }

func (s *Server) Handler() http.Handler { return s.router }

// Run starts the background publisher/enrichment tickers and serves
// HTTP until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	go s.publisher.Run(ctx)
	go s.refreshTorLoop(ctx)

	httpServer := &http.Server{
		Addr:    s.cfg.Listen,
		Handler: s.router,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// Close releases resources New acquired without starting Run (used by
// tests and by `server status`, which only needs a DB handle). Any
// local agent started from the web dashboard is stopped first, so its
// store's lock file is always released cleanly on shutdown.
func (s *Server) Close() error {
	if s.localAgent != nil {
		_ = s.localAgent.StopIfRunning()
	}
	return s.locationService.Close()
}
