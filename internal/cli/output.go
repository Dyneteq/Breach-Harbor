package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// printJSON writes v as indented JSON to w — every data-producing
// command supports --json for scripts.
func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// actionableError pairs a cause with what the user should do about it.
// Every failure path in this CLI must name the likely cause and the
// command that fixes it — never print a bare Go error.
type actionableError struct {
	cause  error
	advice string
}

func (e *actionableError) Error() string {
	if e.advice == "" {
		return e.cause.Error()
	}
	return fmt.Sprintf("%s\n  %s", e.cause.Error(), e.advice)
}

func (e *actionableError) Unwrap() error { return e.cause }

func fail(cause error, advice string) error {
	return &actionableError{cause: cause, advice: advice}
}

func printErr(w io.Writer, err error) {
	fmt.Fprintf(w, "breachharbor: %v\n", err)
}

// ts formats a timestamp the way every scrolling log line in this CLI
// does, e.g. "2026-08-11 09:44:17".
func ts(t time.Time) string { return t.Format("2006-01-02 15:04:05") }

// formatDuration renders a duration the way `agent run`'s dry-run
// banner and `agent status`'s uptime do: "23h58m" / "3h12m" / "46s" —
// coarser than time.Duration.String(), no sub-second noise.
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	switch {
	case h > 0:
		return fmt.Sprintf("%dh%dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm%ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}
