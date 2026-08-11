// Command bh is the short alias for breachharbor — same binary,
// shorter name to type. See cmd/breachharbor for the real entry point.
package main

import (
	"os"

	"github.com/Dyneteq/Breach-Harbor/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args, os.Stdout, os.Stderr))
}
