package cli

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/Dyneteq/Breach-Harbor/internal/agent"
)

func runAgentEnroll(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "breachharbor agent enroll: missing <url>")
		fmt.Fprintln(stderr, "Usage: breachharbor agent enroll <url> --token <token>")
		return 2
	}
	if args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(stdout, "Usage: breachharbor agent enroll <url> --token <token> [--data-dir dir] [--json]")
		return 0
	}
	// <url> is a leading positional argument (see PLAN.md's CLI tree:
	// `agent enroll <url> --token`), which stdlib flag can't parse
	// intermixed with flags — it stops at the first non-flag token. So
	// it's peeled off here, before handing the rest to a normal
	// FlagSet, rather than relying on fs.Args() after Parse.
	serverURL := args[0]
	fs := flag.NewFlagSet("agent enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", agent.DefaultDataDir(), "agent data directory")
	token := fs.String("token", "", "collector bearer token (from the server's dashboard or `breachharbor server`-side collector creation)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *token == "" {
		printErr(stderr, fail(fmt.Errorf("--token is required"), "create a collector on the server first, then pass its token here"))
		return 2
	}

	enrollment, err := agent.Enroll(ctx, nil, serverURL, *token)
	if err != nil {
		printErr(stderr, fail(err, "check the URL, the token, and that the server is reachable"))
		return 1
	}
	if err := agent.SaveEnrollment(*dataDir, enrollment); err != nil {
		printErr(stderr, fail(err, "check --data-dir permissions"))
		return 1
	}

	if *jsonOut {
		if err := printJSON(stdout, map[string]any{
			"server_url":     enrollment.ServerURL,
			"collector_name": enrollment.CollectorName,
			"enrolled_at":    enrollment.EnrolledAt,
		}); err != nil {
			printErr(stderr, err)
			return 1
		}
		return 0
	}

	fmt.Fprintf(stdout, "Enrolled as collector %q with %s.\n", enrollment.CollectorName, enrollment.ServerURL)
	fmt.Fprintln(stdout, "The server's blocklist-signing public key has been pinned (trust-on-first-enroll).")
	fmt.Fprintln(stdout, "Restart `breachharbor agent run` (a currently-running agent only reads enrollment at startup) to start uploading observations and merging the published blocklist.")
	return 0
}
