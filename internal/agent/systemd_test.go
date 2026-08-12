package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type call struct {
	name string
	args []string
}

type fakeSystemdRunner struct {
	calls []call
	run   func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (f *fakeSystemdRunner) LookPath(name string) (string, error) { return "/usr/bin/" + name, nil }

func (f *fakeSystemdRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, call{name: name, args: append([]string(nil), args...)})
	if f.run != nil {
		return f.run(ctx, name, args...)
	}
	return nil, nil
}

func containsCall(calls []call, name, argSubstr string) bool {
	for _, c := range calls {
		if c.name != name {
			continue
		}
		if strings.Contains(strings.Join(c.args, " "), argSubstr) {
			return true
		}
	}
	return false
}

func TestSystemd_Install_WritesUnitAndReloads(t *testing.T) {
	fr := &fakeSystemdRunner{}
	s := &Systemd{run: fr, UnitDir: t.TempDir()}

	if err := s.Install(context.Background(), InstallOptions{BinaryPath: "/usr/local/bin/breachharbor"}); err != nil {
		t.Fatalf("Install: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(s.UnitDir, UnitName))
	if err != nil {
		t.Fatalf("expected the unit file to be written: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "/usr/local/bin/breachharbor agent run") {
		t.Errorf("expected ExecStart to reference the binary path, got:\n%s", content)
	}
	if !strings.Contains(content, "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW") {
		t.Errorf("expected ambient capabilities by default, got:\n%s", content)
	}

	if !containsCall(fr.calls, "systemctl", "daemon-reload") {
		t.Errorf("expected a daemon-reload call, got %+v", fr.calls)
	}
	if !containsCall(fr.calls, "systemctl", "enable --now "+UnitName) {
		t.Errorf("expected an enable --now call, got %+v", fr.calls)
	}
}

func TestSystemd_Install_EnforceFlag(t *testing.T) {
	fr := &fakeSystemdRunner{}
	s := &Systemd{run: fr, UnitDir: t.TempDir()}

	if err := s.Install(context.Background(), InstallOptions{BinaryPath: "/usr/bin/breachharbor", Enforce: true}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(s.UnitDir, UnitName))
	if !strings.Contains(string(data), "--enforce") {
		t.Errorf("expected --enforce baked into ExecStart, got:\n%s", data)
	}
}

func TestSystemd_Install_RootOptionSkipsCapabilities(t *testing.T) {
	fr := &fakeSystemdRunner{}
	s := &Systemd{run: fr, UnitDir: t.TempDir()}

	if err := s.Install(context.Background(), InstallOptions{BinaryPath: "/usr/bin/breachharbor", Root: true}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(s.UnitDir, UnitName))
	if strings.Contains(string(data), "AmbientCapabilities") {
		t.Errorf("expected --root to skip AmbientCapabilities, got:\n%s", data)
	}
}

func TestSystemd_Uninstall_RemovesUnitFile(t *testing.T) {
	fr := &fakeSystemdRunner{}
	dir := t.TempDir()
	s := &Systemd{run: fr, UnitDir: dir}
	if err := s.Install(context.Background(), InstallOptions{BinaryPath: "/usr/bin/breachharbor"}); err != nil {
		t.Fatal(err)
	}

	if err := s.Uninstall(context.Background()); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, UnitName)); !os.IsNotExist(err) {
		t.Errorf("expected the unit file to be removed, stat err = %v", err)
	}
	if !containsCall(fr.calls, "systemctl", "disable --now "+UnitName) {
		t.Errorf("expected a disable --now call, got %+v", fr.calls)
	}
}

func TestSystemd_Uninstall_NoopWhenNeverInstalled(t *testing.T) {
	fr := &fakeSystemdRunner{}
	s := &Systemd{run: fr, UnitDir: t.TempDir()}
	if err := s.Uninstall(context.Background()); err != nil {
		t.Errorf("expected uninstalling a never-installed unit to be a safe no-op, got: %v", err)
	}
	// Must not shell out to systemctl at all in this case — daemon-
	// reload/disable need root (or polkit) on a real system, and a
	// caller with neither (e.g. CI) must still get a clean no-op
	// rather than a permission error for a unit that was never there.
	if len(fr.calls) != 0 {
		t.Errorf("expected zero systemctl calls when nothing was ever installed, got %+v", fr.calls)
	}
}

func TestNewSystemd_DefaultsToRealUnitDir(t *testing.T) {
	s := NewSystemd(nil)
	if s.UnitDir != DefaultUnitDir {
		t.Errorf("UnitDir = %q, want %q", s.UnitDir, DefaultUnitDir)
	}
}
