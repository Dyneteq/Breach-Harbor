package server

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

type fakeLaunchdRunner struct {
	calls []call
	run   func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (f *fakeLaunchdRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
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

func TestLaunchd_Install_WritesPlistAndBootstraps(t *testing.T) {
	fr := &fakeLaunchdRunner{}
	l := &Launchd{run: fr, PlistDir: t.TempDir()}

	if err := l.Install(context.Background(), LaunchdInstallOptions{BinaryPath: "/usr/local/bin/breachharbor", Listen: ":9090"}); err != nil {
		t.Fatalf("Install: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(l.PlistDir, LaunchdLabel+".plist"))
	if err != nil {
		t.Fatalf("expected the plist to be written: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "<string>/usr/local/bin/breachharbor</string>") {
		t.Errorf("expected ProgramArguments to reference the binary path, got:\n%s", content)
	}
	if !strings.Contains(content, "<string>--listen=:9090</string>") {
		t.Errorf("expected ProgramArguments to include the listen address, got:\n%s", content)
	}

	if !containsCall(fr.calls, "launchctl", "bootstrap system") {
		t.Errorf("expected a bootstrap call, got %+v", fr.calls)
	}
	if !containsCall(fr.calls, "launchctl", "enable system/"+LaunchdLabel) {
		t.Errorf("expected an enable call, got %+v", fr.calls)
	}
}

func TestLaunchd_Install_DefaultsListen(t *testing.T) {
	fr := &fakeLaunchdRunner{}
	l := &Launchd{run: fr, PlistDir: t.TempDir()}

	if err := l.Install(context.Background(), LaunchdInstallOptions{BinaryPath: "/usr/bin/breachharbor"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(l.PlistDir, LaunchdLabel+".plist"))
	if !strings.Contains(string(data), "<string>--listen=:8080</string>") {
		t.Errorf("expected the default :8080 listen address, got:\n%s", data)
	}
}

func TestLaunchd_Install_BootsOutExistingBeforeBootstrap(t *testing.T) {
	fr := &fakeLaunchdRunner{}
	l := &Launchd{run: fr, PlistDir: t.TempDir()}

	if err := l.Install(context.Background(), LaunchdInstallOptions{BinaryPath: "/usr/bin/breachharbor"}); err != nil {
		t.Fatal(err)
	}
	if !containsCall(fr.calls, "launchctl", "bootout system/"+LaunchdLabel) {
		t.Errorf("expected a bootout call before bootstrap (idempotent reinstall), got %+v", fr.calls)
	}
}

func TestLaunchd_Uninstall_RemovesPlistFile(t *testing.T) {
	fr := &fakeLaunchdRunner{}
	dir := t.TempDir()
	l := &Launchd{run: fr, PlistDir: dir}
	if err := l.Install(context.Background(), LaunchdInstallOptions{BinaryPath: "/usr/bin/breachharbor"}); err != nil {
		t.Fatal(err)
	}
	fr.calls = nil // isolate Uninstall's own calls

	if err := l.Uninstall(context.Background()); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, LaunchdLabel+".plist")); !os.IsNotExist(err) {
		t.Errorf("expected the plist file to be removed, stat err = %v", err)
	}
	if !containsCall(fr.calls, "launchctl", "bootout system/"+LaunchdLabel) {
		t.Errorf("expected a bootout call, got %+v", fr.calls)
	}
}

func TestLaunchd_Uninstall_NoopWhenNeverInstalled(t *testing.T) {
	fr := &fakeLaunchdRunner{}
	l := &Launchd{run: fr, PlistDir: t.TempDir()}
	if err := l.Uninstall(context.Background()); err != nil {
		t.Errorf("expected uninstalling a never-installed daemon to be a safe no-op, got: %v", err)
	}
	if len(fr.calls) != 0 {
		t.Errorf("expected zero launchctl calls when nothing was ever installed, got %+v", fr.calls)
	}
}

func TestNewLaunchd_DefaultsToRealPlistDir(t *testing.T) {
	l := NewLaunchd(nil)
	if l.PlistDir != DefaultLaunchdDir {
		t.Errorf("PlistDir = %q, want %q", l.PlistDir, DefaultLaunchdDir)
	}
}
