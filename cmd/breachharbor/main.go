// Command breachharbor is the threat blocking agent's CLI: `breachharbor
// agent` collects signals and enforces firewall rules on one machine,
// `breachharbor server` aggregates, enriches, and publishes blocklists.
//
// This same source also builds the `bh` alias binary (see the
// Makefile) — it's a shorter name for the identical program, not a
// separate package, so there's nothing here that multiplexes on
// os.Args[0].
package main

import (
	"os"

	"github.com/Dyneteq/Breach-Harbor/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args, os.Stdout, os.Stderr))
}
