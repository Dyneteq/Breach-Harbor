package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/agent"
	"github.com/Dyneteq/Breach-Harbor/internal/feed"
	"github.com/Dyneteq/Breach-Harbor/internal/firewall"
	"github.com/Dyneteq/Breach-Harbor/internal/logsource"
	"github.com/Dyneteq/Breach-Harbor/internal/store"
	"github.com/Dyneteq/Breach-Harbor/internal/version"
)

// unavailableBackend is a safe firewall.Backend stand-in for when
// firewall.Detect finds nothing usable at startup. A dry-run agent
// never needs a working backend; this only turns into a real error if
// `agent enforce --on` is later requested against it.
type unavailableBackend struct{ err error }

func (u unavailableBackend) Name() string                                     { return "none" }
func (u unavailableBackend) Available(context.Context) error                  { return u.err }
func (u unavailableBackend) Init(context.Context) error                       { return u.err }
func (u unavailableBackend) Flush(context.Context) error                      { return u.err }
func (u unavailableBackend) Block(context.Context, []firewall.Target) error   { return u.err }
func (u unavailableBackend) Unblock(context.Context, []firewall.Target) error { return u.err }
func (u unavailableBackend) List(context.Context) ([]firewall.Target, error)  { return nil, u.err }

func runAgentRun(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agent run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to a config file (not implemented in this build yet — use flags)")
	dataDir := fs.String("data-dir", agent.DefaultDataDir(), "where the agent stores its local state")
	enforce := fs.Bool("enforce", false, "block for real instead of dry-run reporting")
	sourcesFlag := fs.String("sources", "", "comma-separated source names to restrict to (default: all detected)")
	server := fs.String("server", "", "server URL to enroll with (not implemented in this build yet — standalone only)")
	feedFlag := fs.String("feed", "", "comma-separated provider=on|off overrides, e.g. spamhaus=off")
	abuseIPDBKey := fs.String("abuseipdb-key", "", "AbuseIPDB API key (enables the abuseipdb feed)")
	refresh := fs.Duration("refresh", 15*time.Minute, "how often to re-check feeds")
	firewallName := fs.String("firewall", "auto", "firewall backend: nft, ipset, or auto")
	jsonOut := fs.Bool("json", false, "structured JSON log lines instead of the human banner")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *configPath != "" {
		fmt.Fprintln(stderr, "breachharbor agent run --config: not implemented in this build yet (coming in a later milestone) — use flags instead")
		return 1
	}

	cfg := agent.Default()
	cfg.DataDir = *dataDir
	cfg.Enforce = *enforce
	cfg.Server = *server
	cfg.AbuseIPDBKey = *abuseIPDBKey
	cfg.Refresh = *refresh
	cfg.Firewall = *firewallName
	cfg.JSON = *jsonOut
	if *sourcesFlag != "" {
		cfg.Sources = strings.Split(*sourcesFlag, ",")
	}
	cfg.Feeds = parseFeedFlag(*feedFlag)

	if err := cfg.Validate(); err != nil {
		printErr(stderr, fail(err, "check your flags"))
		return 2
	}

	st, err := store.Open(cfg.DataDir)
	if err != nil {
		printErr(stderr, fail(err, "check --data-dir permissions, and that no other agent is already running against it"))
		return 1
	}
	defer st.Close()

	fw, fwErr := firewall.Detect(ctx, cfg.Firewall)
	if fwErr != nil {
		fw = unavailableBackend{err: fwErr}
	}

	sources := selectSources(ctx, cfg.Sources)
	feeds := []feed.Provider{
		feed.NewCachedProvider(feed.NewSpamhaus(), cfg.DataDir, 0),
		feed.NewCachedProvider(feed.NewFirehol(), cfg.DataDir, 0),
		feed.NewCachedProvider(feed.NewTor(), cfg.DataDir, 0),
		feed.NewCachedProvider(feed.NewAbuseIPDB(cfg.AbuseIPDBKey), cfg.DataDir, 0),
	}

	a := agent.New(cfg, st, fw, feeds, sources)
	a.Logf = func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if cfg.JSON {
			_ = printJSON(stdout, map[string]any{"time": time.Now().Format(time.RFC3339), "message": msg})
			return
		}
		fmt.Fprintln(stdout, msg)
	}

	if !cfg.JSON {
		printAgentRunBanner(ctx, stdout, cfg, fw, sources)
	}
	if cfg.Server != "" {
		a.Logf("[%s] --server: not implemented in this build yet (coming in M2) — running standalone", ts(time.Now()))
	}

	if err := a.Run(ctx); err != nil && ctx.Err() == nil {
		printErr(stderr, err)
		return 1
	}
	return 0
}

func printAgentRunBanner(ctx context.Context, stdout io.Writer, cfg agent.Config, fw firewall.Backend, sources []logsource.Source) {
	v := version.Get()
	fmt.Fprintf(stdout, "BREACH::HARBOR agent %s (%s/%s, commit %s)\n\n", v.Version, runtime.GOOS, runtime.GOARCH, v.Commit)

	if !cfg.Enforce {
		state, _ := agent.LoadState(cfg.DataDir)
		remaining := time.Until(state.DryRunUntil)
		fmt.Fprintln(stdout, "┌─────────────────────────────────────────────────────────────────┐")
		fmt.Fprintln(stdout, "│  DRY RUN — nothing is being blocked.                             │")
		fmt.Fprintln(stdout, "│  Observing so you can review what would happen.                  │")
		fmt.Fprintln(stdout, "│  Enable blocking any time with:  breachharbor agent enforce --on │")
		if remaining > 0 {
			fmt.Fprintf(stdout, "│  Time remaining in dry run: %-38s│\n", formatDuration(remaining))
		}
		fmt.Fprintln(stdout, "└─────────────────────────────────────────────────────────────────┘")
		fmt.Fprintln(stdout)
	}

	probes := logsource.ProbeAll(ctx)
	fmt.Fprintf(stdout, "[%s] sources: detected %d of %d possible\n", ts(time.Now()), len(sources), len(probes))
	for _, p := range probes {
		mark := "✘"
		if p.Available {
			mark = "✔"
		}
		fmt.Fprintf(stdout, "  %s %-30s %s\n", mark, p.Source, p.Detail)
	}

	if err := fw.Available(ctx); err == nil {
		fmt.Fprintf(stdout, "[%s] firewall backend: %s\n", ts(time.Now()), fw.Name())
	} else {
		fmt.Fprintf(stdout, "[%s] firewall backend: unavailable (%v)\n", ts(time.Now()), err)
	}

	depth, _ := store.ReadQueueDepth(cfg.DataDir)
	serverLine := "standalone mode, no server enrolled"
	if cfg.Server != "" {
		serverLine = "enrollment requested but not implemented in this build yet — standalone"
	}
	fmt.Fprintf(stdout, "[%s] local queue: %d pending observations (%s)\n", ts(time.Now()), depth, serverLine)
}

// selectSources filters logsource.Detect's result to the given names,
// if any; an empty names list means "every detected source."
func selectSources(ctx context.Context, names []string) []logsource.Source {
	all := logsource.Detect(ctx)
	if len(names) == 0 {
		return all
	}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[strings.TrimSpace(n)] = true
	}
	var filtered []logsource.Source
	for _, s := range all {
		if want[s.Name()] {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// parseFeedFlag parses --feed spamhaus=off,tor=off into a
// provider-name -> enabled map. Malformed entries are silently
// skipped rather than failing startup over a typo in an optional flag.
func parseFeedFlag(raw string) map[string]bool {
	if raw == "" {
		return nil
	}
	out := make(map[string]bool)
	for _, part := range strings.Split(raw, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		name := strings.TrimSpace(kv[0])
		val := strings.ToLower(strings.TrimSpace(kv[1]))
		if name == "" {
			continue
		}
		out[name] = val != "off" && val != "false"
	}
	return out
}
