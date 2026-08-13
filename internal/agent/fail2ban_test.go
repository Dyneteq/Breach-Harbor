package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

// withFakeFail2banClient puts a fake fail2ban-client shell script at the
// front of PATH that prints out and exits with code, restoring the
// original PATH on cleanup. Skips on non-Unix since the fake is a shell
// script.
func withFakeFail2banClient(t *testing.T, out string, code int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake fail2ban-client script requires a POSIX shell")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "fail2ban-client")
	body := fmt.Sprintf("#!/bin/sh\nprintf '%%s' %q\nexit %s\n", out, strconv.Itoa(code))
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestFail2banClient_Banned_EmptyList_ReportsNotBanned(t *testing.T) {
	withFakeFail2banClient(t, "[]", 0)
	c := NewFail2banClient()
	ip := mustAddr(t, "203.0.113.44")
	if c.Banned(context.Background(), ip) {
		t.Error("expected an empty jail list to mean not banned")
	}
}

func TestFail2banClient_Banned_NonEmptyList_ReportsBanned(t *testing.T) {
	withFakeFail2banClient(t, "['sshd']", 0)
	c := NewFail2banClient()
	ip := mustAddr(t, "203.0.113.44")
	if !c.Banned(context.Background(), ip) {
		t.Error("expected a non-empty jail list to mean banned")
	}
}

func TestFail2banClient_Banned_CommandFails_ReportsNotBanned(t *testing.T) {
	withFakeFail2banClient(t, "", 1)
	c := NewFail2banClient()
	ip := mustAddr(t, "203.0.113.44")
	if c.Banned(context.Background(), ip) {
		t.Error("expected a failing command (fail2ban-client missing/unusable) to mean not banned")
	}
}

func TestFail2banClient_Banned_BinaryNotOnPath_ReportsNotBanned(t *testing.T) {
	t.Setenv("PATH", "")
	c := NewFail2banClient()
	ip := mustAddr(t, "203.0.113.44")
	if c.Banned(context.Background(), ip) {
		t.Error("expected a missing fail2ban-client binary to mean not banned")
	}
}
