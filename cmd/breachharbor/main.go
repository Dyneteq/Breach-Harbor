// Command breachharbor is the threat blocking agent's CLI: `breachharbor
// agent` collects signals and enforces firewall rules on one machine,
// `breachharbor server` aggregates, enriches, and publishes blocklists.
package main

import (
	"os"

	"github.com/Dyneteq/Breach-Harbor/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args, os.Stdout, os.Stderr))
}
