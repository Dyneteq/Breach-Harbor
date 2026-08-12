package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/config"
	"github.com/Dyneteq/Breach-Harbor/internal/models"
	"github.com/Dyneteq/Breach-Harbor/internal/server"
	"github.com/Dyneteq/Breach-Harbor/internal/version"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func runServerCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "breachharbor server: missing subcommand")
		printServerUsage(stderr)
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "run":
		return runServerRun(ctx, rest, stdout, stderr)
	case "install":
		return runServerInstall(ctx, rest, stdout, stderr)
	case "status":
		return runServerStatus(ctx, rest, stdout, stderr)
	case "-h", "--help", "help":
		printServerUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "breachharbor server: unknown subcommand %q\n\n", sub)
		printServerUsage(stderr)
		return 2
	}
}

func printServerUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: breachharbor server <subcommand> [flags]

Subcommands:
  run      Run the server in the foreground.
  install  Service unit for the server.
  status   Health, agent count, ingest rate, blocklist freshness.
`)
}

func runServerRun(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("server run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to a config file (not implemented in this build yet — use flags/env)")
	listen := fs.String("listen", ":8080", "address to listen on")
	dataDir := fs.String("data-dir", server.DefaultDataDir(), "where the server stores its signing key (and default SQLite DB)")
	dbPath := fs.String("db", "", "SQLite DB path (default: <data-dir>/breach_harbor.db)")
	publishInterval := fs.Duration("publish-interval", 15*time.Minute, "how often to re-sign and republish the blocklist")
	signKey := fs.String("sign-key", "", "ed25519 signing key path (default: <data-dir>/signing.key)")
	web := fs.Bool("web", true, "serve the HTML dashboard in addition to the API")
	localAgentFlag := fs.Bool("local-agent", false, "let logged-in dashboard users start a local agent.Agent against this host from the web UI (off by default: it can mutate this host's own firewall once enforcing is turned on)")
	jsonOut := fs.Bool("json", false, "structured JSON log lines instead of the human banner")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *configPath != "" {
		fmt.Fprintln(stderr, "breachharbor server run --config: not implemented in this build yet — use flags/env instead")
		return 1
	}

	appCfg, err := config.Load()
	if err != nil {
		printErr(stderr, fail(err, "check your .env / environment variables"))
		return 1
	}

	cfg := server.DefaultConfig()
	cfg.Listen = *listen
	cfg.DataDir = *dataDir
	cfg.PublishInterval = *publishInterval
	cfg.Web = *web
	cfg.LocalAgentEnabled = *localAgentFlag
	cfg.JSON = *jsonOut
	cfg.SignKeyPath = *signKey
	cfg.DBPath = *dbPath
	if cfg.DBPath == "" {
		cfg.DBPath = filepath.Join(cfg.DataDir, "breach_harbor.db")
	}
	appCfg.Database.Path = cfg.DBPath

	srv, err := server.New(cfg, appCfg)
	if err != nil {
		printErr(stderr, fail(err, "check --data-dir/--db permissions"))
		return 1
	}
	defer srv.Close()

	if !cfg.JSON {
		printServerRunBanner(stdout, cfg)
	}

	if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
		printErr(stderr, err)
		return 1
	}
	return 0
}

func printServerRunBanner(stdout io.Writer, cfg server.Config) {
	v := version.Get()
	fmt.Fprintf(stdout, "BREACH::HARBOR server %s (%s/%s, commit %s)\n\n", v.Version, runtime.GOOS, runtime.GOARCH, v.Commit)
	fmt.Fprintf(stdout, "listening on:        %s\n", cfg.Listen)
	fmt.Fprintf(stdout, "data directory:      %s\n", cfg.DataDir)
	fmt.Fprintf(stdout, "database:            %s\n", cfg.DBPath)
	webState := "enabled"
	if !cfg.Web {
		webState = "disabled (API only)"
	}
	fmt.Fprintf(stdout, "dashboard:           %s\n", webState)
	localAgentState := "disabled (enable with --local-agent)"
	if cfg.LocalAgentEnabled {
		localAgentState = "enabled — logged-in users can start a local agent against this host"
	}
	fmt.Fprintf(stdout, "local agent (web):   %s\n", localAgentState)
	fmt.Fprintf(stdout, "blocklist publish:   every %s\n", formatDuration(cfg.PublishInterval))
	fmt.Fprintln(stdout)
}

func runServerInstall(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("server install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":8080", "address the installed service will listen on")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if runtime.GOOS != "linux" {
		printErr(stderr, fail(fmt.Errorf("systemd install is only supported on Linux (this build: %s)", runtime.GOOS), "run `breachharbor server run` directly instead"))
		return 1
	}

	s := server.NewSystemd(nil)
	if err := s.Install(ctx, server.InstallOptions{Listen: *listen}); err != nil {
		printErr(stderr, fail(err, "installing a systemd unit needs root — try again with sudo"))
		return 1
	}

	fmt.Fprintf(stdout, "Installed and started %s.\n", server.UnitName)
	fmt.Fprintf(stdout, "Check status with: sudo systemctl status %s\n", server.UnitName)
	return 0
}

type serverStatusReport struct {
	Running           bool   `json:"running"`
	Listen            string `json:"listen"`
	Database          string `json:"database"`
	CollectorCount    int64  `json:"collector_count"`
	TotalIncidents    int64  `json:"total_incidents"`
	IncidentsLastHour int64  `json:"incidents_last_hour"`
}

func runServerStatus(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("server status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":8080", "address the server listens on (used for the health check)")
	dataDir := fs.String("data-dir", server.DefaultDataDir(), "server data directory")
	dbPath := fs.String("db", "", "SQLite DB path (default: <data-dir>/breach_harbor.db)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	resolvedDB := *dbPath
	if resolvedDB == "" {
		resolvedDB = filepath.Join(*dataDir, "breach_harbor.db")
	}

	report, err := buildServerStatusReport(ctx, *listen, resolvedDB)
	if err != nil {
		printErr(stderr, fail(err, "run `breachharbor server run` first"))
		return 1
	}

	if *jsonOut {
		if err := printJSON(stdout, report); err != nil {
			printErr(stderr, err)
			return 1
		}
		return 0
	}

	state := "not running (or unreachable at " + report.Listen + ")"
	if report.Running {
		state = "running"
	}
	fmt.Fprintf(stdout, "BREACH::HARBOR server — %s\n", state)
	fmt.Fprintf(stdout, "listen:              %s\n", report.Listen)
	fmt.Fprintf(stdout, "database:            %s\n", report.Database)
	fmt.Fprintf(stdout, "collectors:          %d\n", report.CollectorCount)
	fmt.Fprintf(stdout, "incidents (total):   %d\n", report.TotalIncidents)
	fmt.Fprintf(stdout, "incidents (1h):      %d\n", report.IncidentsLastHour)
	return 0
}

func buildServerStatusReport(ctx context.Context, listen, dbPath string) (serverStatusReport, error) {
	report := serverStatusReport{Listen: listen, Database: dbPath}
	report.Running = probeHealth(ctx, listen)

	if _, err := os.Stat(dbPath); err != nil {
		return report, fmt.Errorf("no database found at %s — has `breachharbor server run` been started with this --data-dir/--db before?", dbPath)
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return report, fmt.Errorf("open database %s: %w", dbPath, err)
	}
	if sqlDB, err := db.DB(); err == nil {
		defer sqlDB.Close()
	}

	db.Model(&models.Collector{}).Count(&report.CollectorCount)
	db.Model(&models.Incident{}).Count(&report.TotalIncidents)
	db.Model(&models.Incident{}).Where("created_at >= ?", time.Now().Add(-1*time.Hour)).Count(&report.IncidentsLastHour)

	return report, nil
}

// probeHealth makes a best-effort GET against the server's /health —
// any failure (connection refused, timeout) just means "not running,"
// never an error the caller has to handle.
func probeHealth(ctx context.Context, listen string) bool {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, fmt.Sprintf("http://%s:%s/health", host, port), nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
