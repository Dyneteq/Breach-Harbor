package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/agent"
)

func runAgentEnforce(_ context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agent enforce", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", agent.DefaultDataDir(), "agent data directory")
	on := fs.Bool("on", false, "turn enforcement on")
	off := fs.Bool("off", false, "turn enforcement off")
	jsonOut := fs.Bool("json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *on == *off {
		fmt.Fprintln(stderr, "breachharbor agent enforce: specify exactly one of --on or --off")
		return 2
	}

	state, err := agent.LoadState(*dataDir)
	if err != nil {
		printErr(stderr, fail(err, "run `breachharbor agent run` first"))
		return 1
	}

	state.Enforcing = *on
	if *on {
		if state.EnforcingSince == nil {
			now := time.Now()
			state.EnforcingSince = &now
		}
	} else {
		state.EnforcingSince = nil
	}
	if err := agent.SaveState(*dataDir, state); err != nil {
		printErr(stderr, err)
		return 1
	}

	if *jsonOut {
		_ = printJSON(stdout, map[string]any{"enforcing": state.Enforcing})
		return 0
	}
	if *on {
		fmt.Fprintln(stdout, "Enforcement is now ON.")
		fmt.Fprintln(stdout, "A running `agent run` process picks this up within a few seconds; a fresh `agent run --enforce` starts enforcing immediately.")
	} else {
		fmt.Fprintln(stdout, "Enforcement is now OFF (dry run).")
		fmt.Fprintln(stdout, "Already-blocked IPs remain blocked — run `breachharbor agent flush --yes` to remove all rules.")
	}
	return 0
}
