package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/agent"
	"github.com/Dyneteq/Breach-Harbor/internal/firewall"
	"github.com/Dyneteq/Breach-Harbor/internal/logsource"
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
	report.Checks = append(report.Checks, logSourceChecks(ctx)...)
	report.Checks = append(report.Checks, dataDirCheck())
	report.Checks = append(report.Checks, feedChecks(ctx)...)

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

func dataDirCheck() doctorCheck {
	dir := agent.DefaultDataDir()
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return doctorCheck{Name: "Data directory", Status: "ok", Detail: dir}
	}
	return doctorCheck{Name: "Data directory", Status: "fail", Detail: fmt.Sprintf("%s: does not exist — create it with: mkdir -p %s", dir, dir)}
}

// logSourceChecks reports every logsource.Source's availability, not
// just what's usable — a missing source is "skip" with a human reason,
// never a hard failure (the agent is designed to run fine with zero
// of these detected).
func logSourceChecks(ctx context.Context) []doctorCheck {
	var checks []doctorCheck
	for i, p := range logsource.ProbeAll(ctx) {
		name := ""
		if i == 0 {
			name = "Log sources"
		}
		status := "skip"
		if p.Available {
			status = "ok"
		}
		detail := p.Detail
		if !strings.HasPrefix(detail, p.Source) {
			detail = p.Source + ": " + detail
		}
		checks = append(checks, doctorCheck{Name: name, Status: status, Detail: detail})
	}
	return checks
}

// feedReachabilityTargets intentionally duplicates internal/feed's
// real endpoints rather than importing them — doctor only needs a
// bare reachability probe, not the parsing/caching machinery those
// providers own (see PLAN.md's M1 design notes on small, deliberate
// duplication over cross-package coupling).
var feedReachabilityTargets = []struct{ name, url string }{
	{"spamhaus.org", "https://www.spamhaus.org/drop/drop.txt"},
	{"firehol iblocklist mirror", "https://iplists.firehol.org/files/firehol_level1.netset"},
	{"check.torproject.org", "https://check.torproject.org/torbulkexitlist"},
}

// feedChecks probes each feed endpoint for bare network reachability.
// Any HTTP response at all (even a non-2xx one) counts as reachable —
// this is a connectivity check, not a validity check of the request.
func feedChecks(ctx context.Context) []doctorCheck {
	client := &http.Client{Timeout: 5 * time.Second}
	var checks []doctorCheck
	for i, target := range feedReachabilityTargets {
		name := ""
		if i == 0 {
			name = "Feeds (network)"
		}
		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, target.url, nil)
		if err != nil {
			checks = append(checks, doctorCheck{Name: name, Status: "fail", Detail: target.name + ": " + shortErr(err)})
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			checks = append(checks, doctorCheck{Name: name, Status: "fail", Detail: fmt.Sprintf("%s: unreachable (%s)", target.name, shortErr(err))})
			continue
		}
		resp.Body.Close()
		checks = append(checks, doctorCheck{Name: name, Status: "ok", Detail: fmt.Sprintf("%s: reachable (%dms)", target.name, time.Since(start).Milliseconds())})
	}
	return checks
}
