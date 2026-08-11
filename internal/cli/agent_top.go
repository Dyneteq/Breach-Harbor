package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/agent"
	"github.com/Dyneteq/Breach-Harbor/internal/store"
)

func runAgentTop(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agent top", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", agent.DefaultDataDir(), "agent data directory")
	jsonOut := fs.Bool("json", false, "output as JSON")
	n := fs.Int("n", 20, "max attackers to show")
	watch := fs.Bool("watch", false, "keep refreshing every 2s until Ctrl+C")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	render := func() error {
		offenders, err := store.ReadOffenders(*dataDir)
		if err != nil {
			return err
		}
		if *n > 0 && len(offenders) > *n {
			offenders = offenders[:*n]
		}

		if *jsonOut {
			return printJSON(stdout, offenders)
		}

		state, _ := agent.LoadState(*dataDir)
		mode := "DRY RUN"
		if state.Enforcing {
			mode = "ENFORCING"
		}
		refreshLabel := ""
		if *watch {
			refreshLabel = "   refresh: 2s"
		}
		fmt.Fprintf(stdout, "BREACH::HARBOR — live attackers                          mode: %s%s\n", mode, refreshLabel)
		fmt.Fprintf(stdout, "updated %s\n\n", ts(time.Now()))
		fmt.Fprintf(stdout, "%-5s %-16s %-6s %-7s %-15s %-12s %s\n", "RANK", "IP", "SCORE", "EVENTS", "SOURCE", "STATUS", "SINCE")

		overThreshold, blockedNow := 0, 0
		for i, o := range offenders {
			status := "watching"
			switch {
			case o.Blocked:
				status = "blocked"
				blockedNow++
				overThreshold++
			case o.Score >= agent.DefaultWeights.Threshold:
				status = "would block"
				overThreshold++
			}
			fmt.Fprintf(stdout, "%-5d %-16s %-6d %-7d %-15s %-12s %s\n",
				i+1, o.IP, o.Score, o.Events, strings.Join(o.Sources, ","), status, o.LastSeen.Format("15:04:05"))
		}
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "%d attackers tracked, %d over block threshold, %d currently blocked\n", len(offenders), overThreshold, blockedNow)
		if *watch {
			fmt.Fprintln(stdout, "Press Ctrl+C to exit.")
		}
		return nil
	}

	if !*watch {
		if err := render(); err != nil {
			printErr(stderr, err)
			return 1
		}
		return 0
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := render(); err != nil {
			printErr(stderr, err)
			return 1
		}
		select {
		case <-ctx.Done():
			return 0
		case <-ticker.C:
		}
	}
}
