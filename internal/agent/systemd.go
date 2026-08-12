package agent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
)

// runner executes a system command with a fixed argv array — never a
// shell string. Duplicated locally rather than shared with
// internal/firewall or internal/logsource's own copies (see PLAN.md's
// M1 design notes) — it's ~10 lines and this is now the third
// package that shells out.
type runner interface {
	LookPath(name string) (string, error)
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// DefaultUnitDir is where systemd unit files normally live.
const DefaultUnitDir = "/etc/systemd/system"

// UnitName is the installed unit's filename.
const UnitName = "breachharbor-agent.service"

// unitFileTemplate is intentionally simple text/template rather than
// Sprintf — safer for a file this shape (named fields, not positional
// args). It tries to run without full root via ambient capabilities
// first; --root falls back to a plain unrestricted unit if a
// particular distro's nft/iptables still refuse under those
// capabilities alone.
//
// This has NOT been verified against a real systemd host — there is
// no Linux/systemd machine available in the environment that produced
// this file. Verify AmbientCapabilities actually suffices for your
// firewall backend on a real box before relying on the non-root path;
// --root is the documented fallback if it doesn't.
const unitFileTemplate = `[Unit]
Description=Breach Harbor agent
After=network.target

[Service]
Type=simple
ExecStart={{.BinaryPath}} agent run --data-dir={{.DataDir}}{{if .Enforce}} --enforce{{end}}
Restart=on-failure
RestartSec=5
{{if not .Root}}
# Attempt to run without full root. nftables/ipset+iptables changes
# need CAP_NET_ADMIN; ipset/iptables also touch raw sockets, hence
# CAP_NET_RAW. UNVERIFIED on a real systemd host as of install time —
# if firewall commands still fail under these capabilities alone,
# reinstall with --root.
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true
{{end}}
[Install]
WantedBy=multi-user.target
`

type unitFileData struct {
	BinaryPath string
	DataDir    string
	Enforce    bool
	Root       bool
}

// Systemd installs/uninstalls the agent's systemd unit.
type Systemd struct {
	run     runner
	UnitDir string // overridable so tests render to a temp dir instead of /etc/systemd/system
}

// NewSystemd returns a Systemd manager targeting the real
// /etc/systemd/system. Pass nil for r to use the real system binaries;
// tests pass a fake runner.
func NewSystemd(r runner) *Systemd {
	if r == nil {
		r = execRunner{}
	}
	return &Systemd{run: r, UnitDir: DefaultUnitDir}
}

func (s *Systemd) unitPath() string { return filepath.Join(s.UnitDir, UnitName) }

// InstallOptions configures Install.
type InstallOptions struct {
	// Enforce is baked into the unit's ExecStart as --enforce so the
	// service comes up already enforcing across reboots, if requested.
	Enforce bool
	// BinaryPath overrides the installed binary's path; defaults to
	// os.Executable().
	BinaryPath string
	// Root skips the ambient-capabilities attempt and installs a plain
	// unit with no capability restriction — the documented fallback
	// when a distro's firewall tooling needs more than CAP_NET_ADMIN/
	// CAP_NET_RAW alone.
	Root bool
}

// Install writes the unit file, reloads systemd, and enables+starts
// it. Idempotent: installing over an existing install just rewrites
// the unit and re-enables it.
func (s *Systemd) Install(ctx context.Context, opts InstallOptions) error {
	binPath := opts.BinaryPath
	if binPath == "" {
		p, err := os.Executable()
		if err != nil {
			return fmt.Errorf("determine binary path: %w", err)
		}
		binPath = p
	}

	tmpl := template.Must(template.New("unit").Parse(unitFileTemplate))
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, unitFileData{
		BinaryPath: binPath,
		DataDir:    DefaultDataDir(),
		Enforce:    opts.Enforce,
		Root:       opts.Root,
	}); err != nil {
		return fmt.Errorf("render unit file: %w", err)
	}

	if err := os.MkdirAll(s.UnitDir, 0o755); err != nil {
		return fmt.Errorf("create unit directory %s: %w", s.UnitDir, err)
	}
	if err := os.WriteFile(s.unitPath(), buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write unit file %s: %w", s.unitPath(), err)
	}

	if _, err := s.run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if _, err := s.run.Run(ctx, "systemctl", "enable", "--now", UnitName); err != nil {
		return fmt.Errorf("systemctl enable --now %s: %w", UnitName, err)
	}
	return nil
}

// Uninstall stops, disables, and removes the unit. It only manages
// the unit's own lifecycle — removing agent state (--purge) and
// flushing firewall rules are the CLI layer's job (agent_cmd.go calls
// firewall.Backend.Flush directly, same as `agent flush`), not this
// package's. Calling Uninstall when nothing was ever installed is a
// safe no-op, not an error.
func (s *Systemd) Uninstall(ctx context.Context) error {
	// Nothing was ever installed (or it's already gone): return
	// early without touching systemctl at all. This matters beyond
	// tidiness — systemctl disable/daemon-reload need root (or a
	// polkit rule granting it) on a real system, and a caller with
	// neither must still be able to safely call Uninstall when there
	// is genuinely nothing to remove (e.g. CI, or a fresh checkout).
	if _, err := os.Stat(s.unitPath()); os.IsNotExist(err) {
		return nil
	}

	// Tolerate "unit not loaded"/"not found" here — a unit file that
	// exists on disk but was never actually loaded by systemd (e.g.
	// install failed partway through) must not turn uninstall into a
	// failure either.
	_, _ = s.run.Run(ctx, "systemctl", "disable", "--now", UnitName)

	if err := os.Remove(s.unitPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit file %s: %w", s.unitPath(), err)
	}
	if _, err := s.run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	return nil
}
