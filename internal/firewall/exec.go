package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// runner executes a system command with a fixed argv array — never a
// shell string — so a backend can never be tricked into shell
// interpolation. Tests substitute a fake runner to assert the exact
// argv a backend would issue, without touching a real nft/iptables/
// ipset binary.
type runner interface {
	// LookPath reports whether name is found on PATH, returning its
	// resolved path.
	LookPath(name string) (string, error)
	// Run executes name with args and returns combined stdout+stderr.
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
