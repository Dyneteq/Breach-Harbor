package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMain_Agent_Install_NonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("this assertion only applies to non-Linux hosts; internal/agent/systemd_test.go covers Linux behavior via a fake runner")
	}
	_, stderr, code := run("agent", "install")
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "Linux") {
		t.Errorf("expected a clear Linux-only message, got %q", stderr)
	}
}

func TestMain_Agent_Uninstall_FlushesEvenWithoutFirewallTooling(t *testing.T) {
	dir := t.TempDir()
	// On a machine with neither nft nor iptables (this sandbox),
	// firewall.Detect fails and uninstall should just skip the flush
	// step rather than erroring — uninstall must be safe on an
	// unconfigured host.
	stdout, _, code := run("agent", "uninstall", "--data-dir", dir)
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "Uninstalled") {
		t.Errorf("expected an uninstalled confirmation, got %q", stdout)
	}
}

func TestMain_Agent_Uninstall_Purge_RemovesDataDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "marker"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, code := run("agent", "uninstall", "--data-dir", dir, "--purge")
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("expected --purge to remove the data directory, stat err = %v", err)
	}
}

func TestMain_Agent_Uninstall_WithoutPurge_KeepsDataDir(t *testing.T) {
	dir := t.TempDir()
	stdout, _, _ := run("agent", "uninstall", "--data-dir", dir)
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("expected the data directory to survive without --purge, got: %v", err)
	}
	if !strings.Contains(stdout, "left in place") {
		t.Errorf("expected a message noting the data directory was left in place, got %q", stdout)
	}
}
