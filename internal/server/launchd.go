package server

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"text/template"
)

// DefaultLaunchdDir is where system-wide launchd daemons normally
// live on macOS.
const DefaultLaunchdDir = "/Library/LaunchDaemons"

// LaunchdLabel is the installed daemon's reverse-DNS identifier —
// launchd's equivalent of UnitName.
const LaunchdLabel = "com.breachharbor.server"

// launchdPlistTemplate: like the systemd unit, a plain LaunchDaemon
// with no privilege restriction — the server only binds a TCP port
// and writes to its own data directory/SQLite file, so there's
// nothing here that needs root beyond what installing into
// /Library/LaunchDaemons itself already requires.
//
// This has NOT been verified against a real `launchctl
// bootstrap`/`bootout` on a real macOS host with root — no such
// install was performed in the environment that produced this file.
// Verify on real hardware before relying on it.
const launchdPlistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{.Label}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{.BinaryPath}}</string>
		<string>server</string>
		<string>run</string>
		<string>--data-dir={{.DataDir}}</string>
		<string>--listen={{.Listen}}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>StandardOutPath</key>
	<string>{{.LogPath}}</string>
	<key>StandardErrorPath</key>
	<string>{{.LogPath}}</string>
</dict>
</plist>
`

type launchdPlistData struct {
	Label      string
	BinaryPath string
	DataDir    string
	Listen     string
	LogPath    string
}

// Launchd installs/uninstalls the server's system-wide LaunchDaemon.
type Launchd struct {
	run      runner
	PlistDir string // overridable so tests render to a temp dir instead of /Library/LaunchDaemons
}

// NewLaunchd returns a Launchd manager targeting the real
// /Library/LaunchDaemons. Pass nil for r to use the real launchctl
// binary; tests pass a fake runner.
func NewLaunchd(r runner) *Launchd {
	if r == nil {
		r = execRunner{}
	}
	return &Launchd{run: r, PlistDir: DefaultLaunchdDir}
}

func (l *Launchd) plistPath() string {
	return filepath.Join(l.PlistDir, LaunchdLabel+".plist")
}

// LaunchdInstallOptions configures Install.
type LaunchdInstallOptions struct {
	Listen string
	// BinaryPath overrides the installed binary's path; defaults to
	// os.Executable().
	BinaryPath string
}

// Install writes the plist and (re)loads it via launchctl. Idempotent:
// installing over an existing install boots the old instance out
// first, then bootstraps the freshly written plist back in — same
// "rewrite and re-enable" guarantee as Systemd.Install.
func (l *Launchd) Install(ctx context.Context, opts LaunchdInstallOptions) error {
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

	dataDir := DefaultDataDir()
	tmpl := template.Must(template.New("plist").Parse(launchdPlistTemplate))
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, launchdPlistData{
		Label:      LaunchdLabel,
		BinaryPath: binPath,
		DataDir:    dataDir,
		Listen:     listen,
		LogPath:    filepath.Join(dataDir, "server.log"),
	}); err != nil {
		return fmt.Errorf("render plist: %w", err)
	}

	if err := os.MkdirAll(l.PlistDir, 0o755); err != nil {
		return fmt.Errorf("create launchd directory %s: %w", l.PlistDir, err)
	}
	if err := os.WriteFile(l.plistPath(), buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write plist %s: %w", l.plistPath(), err)
	}

	// Tolerate "not loaded" here — this is the fresh-install case, not
	// a re-install, and must not fail because of that.
	_, _ = l.run.Run(ctx, "launchctl", "bootout", "system/"+LaunchdLabel)

	if _, err := l.run.Run(ctx, "launchctl", "bootstrap", "system", l.plistPath()); err != nil {
		return fmt.Errorf("launchctl bootstrap system %s: %w", l.plistPath(), err)
	}
	if _, err := l.run.Run(ctx, "launchctl", "enable", "system/"+LaunchdLabel); err != nil {
		return fmt.Errorf("launchctl enable system/%s: %w", LaunchdLabel, err)
	}
	return nil
}

// Uninstall boots out and removes the daemon. Calling Uninstall when
// nothing was ever installed is a safe no-op, not an error — same
// contract as Systemd.Uninstall, for the same reason (must work
// without root when there's genuinely nothing to remove).
func (l *Launchd) Uninstall(ctx context.Context) error {
	if _, err := os.Stat(l.plistPath()); os.IsNotExist(err) {
		return nil
	}

	// Tolerate "not loaded"/"no such process" — a plist that exists on
	// disk but was never actually bootstrapped (e.g. install failed
	// partway through) must not turn uninstall into a failure either.
	_, _ = l.run.Run(ctx, "launchctl", "bootout", "system/"+LaunchdLabel)

	if err := os.Remove(l.plistPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist %s: %w", l.plistPath(), err)
	}
	return nil
}
