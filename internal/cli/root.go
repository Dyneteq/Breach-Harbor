// Package cli implements the breachharbor/bh command-line dispatch.
// Both binaries call Main with their own os.Args/os.Stdout/os.Stderr —
// the package never calls os.Exit itself so it stays testable.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// Main is the shared entry point for both the breachharbor and bh
// binaries. The caller is responsible for os.Exit(Main(...)).
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		printUsage(stderr)
		return 2
	}
	// Cancelled on SIGINT/SIGTERM — every long-running foreground loop
	// (`agent run`, `agent top --watch`) depends on this to exit
	// cleanly on Ctrl+C rather than hanging forever.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch args[1] {
	case "agent":
		return runAgentCmd(ctx, args[2:], stdout, stderr)
	case "server":
		return runServerCmd(ctx, args[2:], stdout, stderr)
	case "doctor":
		return runDoctorCmd(ctx, args[2:], stdout, stderr)
	case "version":
		return runVersionCmd(ctx, args[2:], stdout, stderr)
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "breachharbor: unknown command %q\n\n", args[1])
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `breachharbor — the threat blocking agent you can set up in five minutes.

Usage:
  breachharbor agent <run|install|uninstall|status|top|enforce|flush|sources|enroll> [flags]
  breachharbor server <run|install|status> [flags]
  breachharbor doctor [--json]
  breachharbor version [--json]

Run 'breachharbor <command> --help' for flags on a specific command.
`)
}
