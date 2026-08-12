package server

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

// runner mirrors internal/agent/systemd.go's own copy — see that
// file's comment on why this ~10-line seam is duplicated per package
// rather than shared.
type runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

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
const UnitName = "breachharbor-server.service"

// unitFileTemplate: unlike the agent, the server never touches the
// firewall — it only binds a TCP port and writes to its own data
// directory/SQLite file — so there's no ambient-capabilities question
// here, just a plain unit running as the invoking user.
const unitFileTemplate = `[Unit]
Description=Breach Harbor server
After=network.target

[Service]
Type=simple
ExecStart={{.BinaryPath}} server run --data-dir={{.DataDir}} --listen={{.Listen}}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`

type unitFileData struct {
	BinaryPath string
	DataDir    string
	Listen     string
}

// Systemd installs/uninstalls the server's systemd unit.
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
	Listen string
	// BinaryPath overrides the installed binary's path; defaults to
	// os.Executable().
	BinaryPath string
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
	listen := opts.Listen
	if listen == "" {
		listen = ":8080"
	}

	tmpl := template.Must(template.New("unit").Parse(unitFileTemplate))
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, unitFileData{
		BinaryPath: binPath,
		DataDir:    DefaultDataDir(),
		Listen:     listen,
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
