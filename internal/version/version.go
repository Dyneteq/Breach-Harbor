// Package version holds build metadata populated at compile time via
// -ldflags (see the Makefile). All values have sane fallbacks so
// `go run`/`go build` without ldflags still produces sensible output.
package version

import "fmt"

var (
	// Version is the release version, e.g. "v0.5.0". Set via -ldflags.
	Version = "dev"
	// Commit is the git commit SHA the binary was built from.
	Commit = "unknown"
	// Date is the build timestamp in RFC3339.
	Date = "unknown"
	// Signed indicates whether this binary was produced by the signed
	// release pipeline (see M3). Never set outside that pipeline.
	Signed = "no"
)

// String returns a one-line human summary, e.g. what `breachharbor
// version` prints.
func String() string {
	return fmt.Sprintf("breachharbor %s\ncommit:   %s\nbuilt:    %s\nsigned:   %s", Version, Commit, Date, Signed)
}

// Info is the structured form used for --json output.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
	Signed  bool   `json:"signed"`
}

// Get returns the current build info as a structured value.
func Get() Info {
	return Info{
		Version: Version,
		Commit:  Commit,
		Date:    Date,
		Signed:  Signed == "yes",
	}
}
