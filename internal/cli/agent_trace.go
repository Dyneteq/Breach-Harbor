package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"

	"github.com/Dyneteq/Breach-Harbor/internal/agent"
)

// agentTraceLinePattern splits a rendered agent.Agent.emit() line back
// into its columns: emit's own doc comment (internal/agent/agent.go)
// states "HH:MM:SS, a left-aligned tag, then a free-form message" as
// the stable shape every line follows, the same contract
// internal/server/localagent.go's dashboard log buffer parses on.
var agentTraceLinePattern = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(.*)$`)

const (
	ansiReset  = "\x1b[0m"
	ansiDim    = "\x1b[90m"
	ansiAccent = "\x1b[36m"
	ansiDanger = "\x1b[31m"
	ansiWarn   = "\x1b[33m"
)

// runAgentTrace attaches to an already-running agent and streams its
// live status log with the same colored terminal look this project's
// marketing site demos (index.html). It exists because in normal
// production use the agent runs headless under systemd
// (breachharbor-agent.service, installed by `agent install`), so
// there is no foreground `agent run` to watch. This tails that service's
// journal instead of running a second agent instance (which the data
// dir's lock file would refuse anyway).
func runAgentTrace(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agent trace", flag.ContinueOnError)
	fs.SetOutput(stderr)
	unit := fs.String("unit", agent.UnitName, "systemd unit to follow")
	lines := fs.Int("lines", 20, "lines of backlog to show before following live")
	noColor := fs.Bool("no-color", false, "disable ANSI colors")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	journalctl, err := lookPathJournalctl()
	if err != nil {
		printErr(stderr, fail(
			fmt.Errorf("journalctl not found"),
			"agent trace attaches to a systemd-managed agent (breachharbor agent install); it only works on Linux hosts with systemd. Running your own foreground `breachharbor agent run` already prints this same live log directly.",
		))
		return 1
	}

	color := !*noColor && os.Getenv("NO_COLOR") == "" && isTerminal(stdout)

	cmd := exec.CommandContext(ctx, journalctl, "-u", *unit, "-n", fmt.Sprint(*lines), "-f", "-o", "cat", "--no-pager")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		printErr(stderr, fail(err, "check journalctl is installed and readable by this user (try with sudo)"))
		return 1
	}
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		printErr(stderr, fail(err, fmt.Sprintf("check the %s unit exists (breachharbor agent install) and you can read the journal: try `sudo breachharbor agent trace`", *unit)))
		return 1
	}

	fmt.Fprintf(stdout, "tracing %s (Ctrl+C to stop)\n\n", *unit)

	scanner := bufio.NewScanner(pipe)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		writeTraceLine(stdout, scanner.Text(), color)
	}

	if err := cmd.Wait(); err != nil && ctx.Err() == nil {
		printErr(stderr, fail(err, fmt.Sprintf("check the %s unit exists and is running: systemctl status %s", *unit, *unit)))
		return 1
	}
	return 0
}

// writeTraceLine re-renders one journal line in the marketing site's
// color scheme: dim timestamp, accent-colored ready/mode/summary tags,
// red would/block tags, yellow warn. Lines that don't match the
// expected shape (e.g. a stray non-agent log line in the same unit)
// print unmodified rather than being dropped.
func writeTraceLine(w io.Writer, line string, color bool) {
	if !color {
		fmt.Fprintln(w, line)
		return
	}
	match := agentTraceLinePattern.FindStringSubmatch(line)
	if match == nil {
		fmt.Fprintln(w, line)
		return
	}
	timeStr, tag, message := match[1], match[2], match[3]

	tagColor := ""
	switch tag {
	case "ready", "mode", "summary":
		tagColor = ansiAccent
	case "would", "block":
		tagColor = ansiDanger
	case "warn":
		tagColor = ansiWarn
	}

	fmt.Fprintf(w, "%s%s%s %s%-7s%s %s\n", ansiDim, timeStr, ansiReset, tagColor, tag, ansiReset, message)
}

// lookPathJournalctl is exec.LookPath("journalctl") pulled into its
// own function so TestMain_Agent_Trace_NoJournalctl can check the same
// not-found condition runAgentTrace acts on, without needing to run
// the whole command.
func lookPathJournalctl() (string, error) {
	return exec.LookPath("journalctl")
}

// isTerminal reports whether w is a character device (an interactive
// terminal, not a pipe/file/bytes.Buffer): used to decide whether
// ANSI color codes are safe to write. Deliberately hand-rolled rather
// than pulling in golang.org/x/term for one check (this repo's
// standing convention, see internal/agent/systemd.go's runner
// interface comment for another instance of it).
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
