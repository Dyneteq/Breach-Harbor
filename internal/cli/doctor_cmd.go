package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	"github.com/Dyneteq/Breach-Harbor/internal/firewall"
)

// doctorCheck is one line of `breachharbor doctor` output. Status is
// one of "ok", "skip", or "fail".
type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type doctorReport struct {
	Checks []doctorCheck `json:"checks"`
}

func runDoctorCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	report := doctorReport{}
	report.Checks = append(report.Checks, osArchCheck(), buildCheck(), permissionsCheck())
	report.Checks = append(report.Checks, firewallChecks(ctx)...)
	report.Checks = append(report.Checks, dataDirCheck())

	if *jsonOut {
		if err := printJSON(stdout, report); err != nil {
			printErr(stderr, err)
			return 1
		}
		return doctorExitCode(report)
	}

	fmt.Fprintln(stdout, "BREACH::HARBOR doctor — environment check")
	fmt.Fprintln(stdout)
	var ok, skip, failN int
	for _, c := range report.Checks {
		fmt.Fprintf(stdout, "%-18s %-50s %s\n", c.Name, c.Detail, c.Status)
		switch c.Status {
		case "ok":
			ok++
		case "skip":
			skip++
		case "fail":
			failN++
		}
	}
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "%d ok, %d skip, %d fail\n", ok, skip, failN)
	if failN > 0 {
		fmt.Fprintln(stdout, "Fix the failed item(s) above, then re-run doctor.")
	}
	return doctorExitCode(report)
}

func doctorExitCode(r doctorReport) int {
	for _, c := range r.Checks {
		if c.Status == "fail" {
			return 1
		}
	}
	return 0
}

func osArchCheck() doctorCheck {
	return doctorCheck{Name: "OS/ARCH", Status: "ok", Detail: fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)}
}

func buildCheck() doctorCheck {
	// CGO usage isn't reliably introspectable at runtime, so this
	// reports what the release build process guarantees rather than
	// probing for it.
	return doctorCheck{Name: "Build", Status: "ok", Detail: "static binary, CGO disabled"}
}

func permissionsCheck() doctorCheck {
	u, err := user.Current()
	if err != nil {
		return doctorCheck{Name: "Permissions", Status: "skip", Detail: "could not determine current user: " + shortErr(err)}
	}
	if u.Uid == "0" {
		return doctorCheck{Name: "Permissions", Status: "ok", Detail: "running as root — firewall commands available"}
	}
	return doctorCheck{Name: "Permissions", Status: "ok", Detail: fmt.Sprintf("running as uid=%s (not root) — firewall commands need sudo", u.Uid)}
}

func firewallChecks(ctx context.Context) []doctorCheck {
	var checks []doctorCheck
	if err := firewall.NewNFTables(nil).Available(ctx); err != nil {
		checks = append(checks, doctorCheck{Name: "Firewall backend", Status: "skip", Detail: "nftables: not available (" + shortErr(err) + ")"})
	} else {
		checks = append(checks, doctorCheck{Name: "Firewall backend", Status: "ok", Detail: "nftables detected"})
	}
	if err := firewall.NewIPSet(nil).Available(ctx); err != nil {
		checks = append(checks, doctorCheck{Name: "", Status: "skip", Detail: "iptables/ipset: not available (" + shortErr(err) + ")"})
	} else {
		checks = append(checks, doctorCheck{Name: "", Status: "ok", Detail: "iptables/ipset detected as fallback"})
	}
	return checks
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 60 {
		s = s[:60] + "..."
	}
	return s
}

// defaultDataDir mirrors the default `breachharbor agent run
// --data-dir` will use once the agent package lands in M1: a system
// path when root, a per-user path otherwise.
func defaultDataDir() string {
	if os.Geteuid() == 0 {
		return "/var/lib/breachharbor"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "breachharbor")
	}
	return filepath.Join(home, ".local", "state", "breachharbor")
}

func dataDirCheck() doctorCheck {
	dir := defaultDataDir()
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return doctorCheck{Name: "Data directory", Status: "ok", Detail: dir}
	}
	return doctorCheck{Name: "Data directory", Status: "fail", Detail: fmt.Sprintf("%s: does not exist — create it with: mkdir -p %s", dir, dir)}
}
