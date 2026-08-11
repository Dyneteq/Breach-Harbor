package cli

import (
	"context"
	"fmt"
	"io"
)

func runServerCmd(_ context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "breachharbor server: missing subcommand")
		printServerUsage(stderr)
		return 2
	}
	switch sub := args[0]; sub {
	case "run", "install", "status":
		fmt.Fprintf(stderr, "breachharbor server %s: not implemented in this build yet (coming in a later milestone)\n", sub)
		return 1
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
