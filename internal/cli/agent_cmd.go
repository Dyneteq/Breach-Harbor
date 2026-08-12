package cli

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/Dyneteq/Breach-Harbor/internal/firewall"
)

func runAgentCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "breachharbor agent: missing subcommand")
		printAgentUsage(stderr)
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "flush":
		return runAgentFlush(ctx, rest, stdout, stderr)
	case "run":
		return runAgentRun(ctx, rest, stdout, stderr)
	case "install":
		return runAgentInstall(ctx, rest, stdout, stderr)
	case "uninstall":
		return runAgentUninstall(ctx, rest, stdout, stderr)
	case "status":
		return runAgentStatus(ctx, rest, stdout, stderr)
	case "top":
		return runAgentTop(ctx, rest, stdout, stderr)
	case "trace":
		return runAgentTrace(ctx, rest, stdout, stderr)
	case "enforce":
		return runAgentEnforce(ctx, rest, stdout, stderr)
	case "sources":
		return runAgentSources(ctx, rest, stdout, stderr)
	case "enroll":
		return runAgentEnroll(ctx, rest, stdout, stderr)
	case "-h", "--help", "help":
		printAgentUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "breachharbor agent: unknown subcommand %q\n\n", sub)
		printAgentUsage(stderr)
		return 2
	}
}

func printAgentUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: breachharbor agent <subcommand> [flags]

Subcommands:
  run        Foreground. Auto-detects sources. Dry run unless --enforce.
  install    Write/enable a daemon (systemd on Linux, launchd on macOS).
  uninstall  Remove the service. Implies flush.
  status     What's running, watched, blocked, since when.
  top        Live top-attackers view.
  trace      Attach to an installed service and stream its live log, in color.
  enforce    Switch observe-only <-> enforcing (--on|--off).
  flush      Remove every rule this agent added. Always safe.
  sources    List detected log sources and their state.
  enroll     Point this agent at a server: enroll <url>.
`)
}

func runAgentFlush(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agent flush", flag.ContinueOnError)
	fs.SetOutput(stderr)
	firewallName := fs.String("firewall", "auto", "firewall backend: nft, ipset, iptables-nft, ufw, pf, or auto")
	jsonOut := fs.Bool("json", false, "output as JSON")
	yes := fs.Bool("yes", false, "actually remove rules (without this flag, only reports what would be removed)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	backend, err := firewall.Detect(ctx, *firewallName)
	if err != nil {
		printErr(stderr, fail(err, "install nftables, iptables+ipset, or iptables-nft, or run `ufw enable` (Linux), or use pfctl (macOS/OpenBSD), then retry"))
		return 1
	}

	before, err := backend.List(ctx)
	if err != nil {
		printErr(stderr, fail(err, "run `breachharbor doctor` to check firewall backend status"))
		return 1
	}

	if !*yes {
		if *jsonOut {
			_ = printJSON(stdout, map[string]any{"backend": backend.Name(), "would_remove": len(before)})
		} else {
			fmt.Fprintf(stdout, "Would remove %d rule(s) added by this agent (backend: %s).\n", len(before), backend.Name())
			fmt.Fprintln(stdout, "Run again with --yes to actually remove them.")
		}
		return 0
	}

	if err := backend.Flush(ctx); err != nil {
		printErr(stderr, fail(err, "re-run with elevated privileges: sudo breachharbor agent flush --yes"))
		return 1
	}

	if *jsonOut {
		_ = printJSON(stdout, map[string]any{"backend": backend.Name(), "removed": len(before)})
	} else {
		fmt.Fprintf(stdout, "Removed %d rule(s) added by this agent (backend: %s). Nothing else was touched.\n", len(before), backend.Name())
	}
	return 0
}
