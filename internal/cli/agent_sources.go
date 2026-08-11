package cli

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/Dyneteq/Breach-Harbor/internal/logsource"
)

func runAgentSources(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agent sources", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	results := logsource.ProbeAll(ctx)

	if *jsonOut {
		if err := printJSON(stdout, results); err != nil {
			printErr(stderr, err)
			return 1
		}
		return 0
	}

	fmt.Fprintln(stdout, "BREACH::HARBOR — log sources")
	fmt.Fprintln(stdout)
	var available int
	for _, r := range results {
		mark := "✘"
		if r.Available {
			mark = "✔"
			available++
		}
		fmt.Fprintf(stdout, "  %s %-24s %s\n", mark, r.Source, r.Detail)
	}
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "%d of %d sources detected\n", available, len(results))
	return 0
}
