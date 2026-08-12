package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/Dyneteq/Breach-Harbor/internal/agent"
	"github.com/Dyneteq/Breach-Harbor/internal/firewall"
)

func runAgentInstall(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agent install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	enforce := fs.Bool("enforce", false, "start enforcing immediately instead of a 24h dry run")
	root := fs.Bool("root", false, "install a full-root unit instead of attempting ambient capabilities (Linux only)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	switch runtime.GOOS {
	case "linux":
		s := agent.NewSystemd(nil)
		if err := s.Install(ctx, agent.InstallOptions{Enforce: *enforce, Root: *root}); err != nil {
			printErr(stderr, fail(err, "installing a systemd unit needs root — try again with sudo"))
			return 1
		}
		fmt.Fprintf(stdout, "Installed and started %s.\n", agent.UnitName)
		fmt.Fprintf(stdout, "Check status with: sudo systemctl status %s\n", agent.UnitName)

	case "darwin":
		l := agent.NewLaunchd(nil)
		if err := l.Install(ctx, agent.LaunchdInstallOptions{Enforce: *enforce}); err != nil {
			printErr(stderr, fail(err, "installing a LaunchDaemon needs root — try again with sudo"))
			return 1
		}
		fmt.Fprintf(stdout, "Installed and started %s.\n", agent.LaunchdLabel)
		fmt.Fprintf(stdout, "Check status with: sudo launchctl list | grep %s\n", agent.LaunchdLabel)
		fmt.Fprintf(stdout, "Logs at: %s\n", agent.DefaultDataDir()+"/agent.log")

	default:
		printErr(stderr, fail(fmt.Errorf("daemon install is only supported on Linux and macOS (this build: %s)", runtime.GOOS), "run `breachharbor agent run` directly instead"))
		return 1
	}

	if !*enforce {
		fmt.Fprintln(stdout, "Running in dry run. Enable blocking any time with: breachharbor agent enforce --on")
	}
	return 0
}

func runAgentUninstall(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agent uninstall", flag.ContinueOnError)
	fs.SetOutput(stderr)
	purge := fs.Bool("purge", false, "also remove the agent's data directory")
	dataDir := fs.String("data-dir", agent.DefaultDataDir(), "agent data directory")
	firewallName := fs.String("firewall", "auto", "firewall backend: nft, ipset, ufw, pf, or auto")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	switch runtime.GOOS {
	case "linux":
		s := agent.NewSystemd(nil)
		if err := s.Uninstall(ctx); err != nil {
			printErr(stderr, fail(err, "uninstalling the systemd unit needs root — try again with sudo"))
			return 1
		}
	case "darwin":
		l := agent.NewLaunchd(nil)
		if err := l.Uninstall(ctx); err != nil {
			printErr(stderr, fail(err, "uninstalling the LaunchDaemon needs root — try again with sudo"))
			return 1
		}
	}

	// Uninstall implies flush — remove every rule this agent ever
	// added, same guarantee as `agent flush --yes`.
	if backend, err := firewall.Detect(ctx, *firewallName); err == nil {
		if err := backend.Flush(ctx); err != nil {
			printErr(stderr, fail(err, "run `breachharbor agent flush --yes` manually to finish removing rules"))
			return 1
		}
	}

	if *purge {
		if err := os.RemoveAll(*dataDir); err != nil {
			printErr(stderr, fail(err, "remove the data directory manually: "+*dataDir))
			return 1
		}
	}

	fmt.Fprintln(stdout, "Uninstalled. Firewall rules flushed.")
	if *purge {
		fmt.Fprintln(stdout, "Data directory removed.")
	} else {
		fmt.Fprintf(stdout, "Data directory left in place: %s (remove it yourself, or re-run with --purge)\n", *dataDir)
	}
	return 0
}
