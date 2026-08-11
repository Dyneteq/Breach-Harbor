package cli

import (
	"encoding/json"
	"fmt"
	"io"
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
