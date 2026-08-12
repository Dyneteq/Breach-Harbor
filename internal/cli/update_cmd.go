package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Dyneteq/Breach-Harbor/internal/selfupdate"
	"github.com/Dyneteq/Breach-Harbor/internal/version"
)

// siblingBinaryNames are the two names `make build`/install.sh drop
// alongside each other — identical binaries, so an update replaces
// both when both are present next to the one currently running.
var siblingBinaryNames = [2]string{"breachharbor", "bh"}

// newUpdater is a var, not a direct selfupdate.New() call, so tests
// can point it at an httptest server instead of the real GitHub API.
var newUpdater = selfupdate.New

// executableOverride is a var, not a direct os.Executable() call, so
// tests can install over a throwaway file instead of the real test
// binary.
var executableOverride = os.Executable

func runUpdateCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	checkOnly := fs.Bool("check", false, "only check for a newer release, don't install it")
	toTag := fs.String("version", "latest", "release tag to install, e.g. v0.3.0")
	jsonOut := fs.Bool("json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	u := newUpdater()
	rel, err := u.Resolve(ctx, *toTag)
	if err != nil {
		printErr(stderr, fail(err, "check your network connection, or see https://github.com/Dyneteq/Breach-Harbor/releases for manual downloads"))
		return 1
	}
	upToDate := rel.Tag == version.Version

	if *jsonOut {
		result := struct {
			Current   string `json:"current"`
			Latest    string `json:"latest"`
			UpToDate  bool   `json:"up_to_date"`
			Installed bool   `json:"installed"`
		}{Current: version.Version, Latest: rel.Tag, UpToDate: upToDate}

		if !upToDate && !*checkOnly {
			if err := doUpdate(ctx, u, rel, stdout, true); err != nil {
				printErr(stderr, fail(err, updateFailAdvice))
				return 1
			}
			result.Installed = true
		}
		if err := printJSON(stdout, result); err != nil {
			printErr(stderr, err)
			return 1
		}
		return 0
	}

	if upToDate {
		fmt.Fprintf(stdout, "Already up to date (%s).\n", version.Version)
		return 0
	}

	if *checkOnly {
		fmt.Fprintf(stdout, "A newer release is available: %s (current: %s)\n", rel.Tag, version.Version)
		fmt.Fprintln(stdout, "Run 'breachharbor update' to install it.")
		return 0
	}

	if err := doUpdate(ctx, u, rel, stdout, false); err != nil {
		printErr(stderr, fail(err, updateFailAdvice))
		return 1
	}
	fmt.Fprintf(stdout, "Updated to %s. Run 'breachharbor version' to confirm.\n", rel.Tag)
	return 0
}

const updateFailAdvice = "try 'sudo breachharbor update' if the binary lives in a root-owned directory, or reinstall with: curl -fsSL https://breachharbor.com/install.sh | sh"

// doUpdate fetches rel once and installs it over every sibling binary
// (breachharbor/bh) found next to the currently running executable —
// install.sh drops both, so an update should keep both in sync.
func doUpdate(ctx context.Context, u *selfupdate.Updater, rel selfupdate.Release, stdout io.Writer, quiet bool) error {
	exe, err := executableOverride()
	if err != nil {
		return fmt.Errorf("determine the running binary's path: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	if !quiet {
		fmt.Fprintf(stdout, "Updating %s -> %s...\n", version.Version, rel.Tag)
	}

	binPath, cleanup, err := u.Fetch(ctx, rel)
	if err != nil {
		return err
	}
	defer cleanup()

	dir := filepath.Dir(exe)
	for _, name := range siblingBinaryNames {
		target := filepath.Join(dir, name)
		if target != exe {
			if _, err := os.Stat(target); err != nil {
				continue // sibling not present alongside this binary; skip it
			}
		}
		if err := selfupdate.Install(binPath, target); err != nil {
			return fmt.Errorf("install %s: %w", target, err)
		}
	}
	return nil
}
