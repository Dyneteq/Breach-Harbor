package logsource

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// runner executes a system command with a fixed argv array — never a
// shell string. This mirrors internal/firewall/exec.go's seam; it is
// duplicated rather than shared because that package is frozen for
// this milestone and the interface is small enough that a shared
// package isn't worth it yet (see PLAN.md).
type runner interface {
	LookPath(name string) (string, error)
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}
