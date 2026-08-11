package cli

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/Dyneteq/Breach-Harbor/internal/version"
)

func runVersionCmd(_ context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *jsonOut {
		if err := printJSON(stdout, version.Get()); err != nil {
			printErr(stderr, err)
			return 1
		}
		return 0
	}
	fmt.Fprintln(stdout, version.String())
	return 0
}
