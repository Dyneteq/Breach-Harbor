package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/agent"
	"github.com/Dyneteq/Breach-Harbor/internal/firewall"
	"github.com/Dyneteq/Breach-Harbor/internal/logsource"
	"github.com/Dyneteq/Breach-Harbor/internal/store"
)

// processAlive reports whether pid is a live process, via the
// standard POSIX "signal 0" liveness probe (delivers nothing, just
// checks permission/existence). Duplicated from internal/store's copy
// — small enough that a shared package isn't worth it for two sites.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

type statusReport struct {
	Running        bool       `json:"running"`
	PID            int        `json:"pid,omitempty"`
	Mode           string     `json:"mode"`
	Since          time.Time  `json:"since"`
	EnforcingSince *time.Time `json:"enforcing_since,omitempty"`
	DryRunUntil    *time.Time `json:"dry_run_until,omitempty"`
	Firewall       string     `json:"firewall"`
	Sources        []string   `json:"sources"`
	Server         string     `json:"server"`
	QueueDepth     int        `json:"queue_depth"`
	OffenderCount  int        `json:"offender_count"`
	BlockedCount   int        `json:"blocked_count"`
}

func runAgentStatus(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agent status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", agent.DefaultDataDir(), "agent data directory")
	jsonOut := fs.Bool("json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	report, err := buildStatusReport(ctx, *dataDir)
	if err != nil {
		printErr(stderr, fail(err, "run `breachharbor agent run` first"))
		return 1
	}

	if *jsonOut {
		if err := printJSON(stdout, report); err != nil {
			printErr(stderr, err)
			return 1
		}
		return 0
	}

	if !report.Running {
		fmt.Fprintln(stdout, "BREACH::HARBOR agent — not running")
		fmt.Fprintf(stdout, "No live process found for data dir %s.\n", *dataDir)
		fmt.Fprintln(stdout, "Start it now:      breachharbor agent run        (foreground, for testing)")
		fmt.Fprintln(stdout, "Or install it:     sudo breachharbor agent install   (systemd, runs at boot)")
		return 0
	}

	fmt.Fprintf(stdout, "BREACH::HARBOR agent — running (pid %d, uptime %s)\n", report.PID, formatDuration(time.Since(report.Since)))
	fmt.Fprintf(stdout, "mode:            %s\n", report.Mode)
	fmt.Fprintf(stdout, "firewall:        %s\n", report.Firewall)
	if len(report.Sources) > 0 {
		fmt.Fprintf(stdout, "sources:         %d active (%s) — see `breachharbor agent sources`\n", len(report.Sources), strings.Join(report.Sources, ", "))
	} else {
		fmt.Fprintln(stdout, "sources:         none detected — see `breachharbor agent sources`")
	}
	fmt.Fprintf(stdout, "server:          %s\n", report.Server)
	fmt.Fprintf(stdout, "queue:           %d pending observations\n", report.QueueDepth)
	fmt.Fprintf(stdout, "blocked now:     %d IPs (%d tracked total)\n", report.BlockedCount, report.OffenderCount)
	if report.DryRunUntil != nil {
		fmt.Fprintf(stdout, "dry run until:   %s (%s remaining)\n", ts(*report.DryRunUntil), formatDuration(time.Until(*report.DryRunUntil)))
	}
	fmt.Fprintf(stdout, "since:           %s\n", ts(report.Since))
	return 0
}

func buildStatusReport(ctx context.Context, dataDir string) (statusReport, error) {
	state, err := agent.LoadState(dataDir)
	if err != nil {
		return statusReport{}, err
	}

	offenders, err := store.ReadOffenders(dataDir)
	if err != nil {
		return statusReport{}, err
	}
	depth, err := store.ReadQueueDepth(dataDir)
	if err != nil {
		return statusReport{}, err
	}

	blocked := 0
	for _, o := range offenders {
		if o.Blocked {
			blocked++
		}
	}

	mode := "dry run"
	if state.Enforcing {
		mode = "enforcing"
	}

	firewallLine := "unavailable"
	if fw, err := firewall.Detect(ctx, "auto"); err == nil {
		firewallLine = fw.Name()
		if targets, err := fw.List(ctx); err == nil {
			firewallLine = fmt.Sprintf("%s (%d addresses blocked)", fw.Name(), len(targets))
		}
	}

	var sourceNames []string
	for _, s := range logsource.Detect(ctx) {
		sourceNames = append(sourceNames, s.Name())
	}

	server := "not enrolled (standalone) — run `breachharbor agent enroll <url>` to connect one"
	if enrollment, found, eerr := agent.LoadEnrollment(dataDir); eerr == nil && found {
		server = fmt.Sprintf("enrolled with %s as %q (since %s)", enrollment.ServerURL, enrollment.CollectorName, ts(enrollment.EnrolledAt))
	}

	report := statusReport{
		Running:        state.PID != 0 && processAlive(state.PID),
		PID:            state.PID,
		Mode:           mode,
		Since:          state.StartedAt,
		EnforcingSince: state.EnforcingSince,
		Firewall:       firewallLine,
		Sources:        sourceNames,
		Server:         server,
		QueueDepth:     depth,
		OffenderCount:  len(offenders),
		BlockedCount:   blocked,
	}
	if !state.Enforcing && time.Now().Before(state.DryRunUntil) {
		d := state.DryRunUntil
		report.DryRunUntil = &d
	}
	return report, nil
}
