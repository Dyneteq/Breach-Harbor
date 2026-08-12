package cli

import (
	"bytes"
	"strings"
	"testing"
)

func run(args ...string) (stdout, stderr string, code int) {
	var out, err bytes.Buffer
	code = Main(append([]string{"breachharbor"}, args...), &out, &err)
	return out.String(), err.String(), code
}

func TestMain_NoArgs(t *testing.T) {
	_, stderr, code := run()
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("expected usage text on stderr, got %q", stderr)
	}
}

func TestMain_UnknownCommand(t *testing.T) {
	_, stderr, code := run("bogus")
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr, `unknown command "bogus"`) {
		t.Errorf("expected unknown-command message, got %q", stderr)
	}
}

func TestMain_Help(t *testing.T) {
	stdout, _, code := run("--help")
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "breachharbor agent") {
		t.Errorf("expected usage text on stdout, got %q", stdout)
	}
}

func TestMain_Version(t *testing.T) {
	stdout, _, code := run("version")
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "breachharbor") {
		t.Errorf("expected version banner, got %q", stdout)
	}
}

func TestMain_VersionJSON(t *testing.T) {
	stdout, _, code := run("version", "--json")
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout, `"version"`) {
		t.Errorf("expected JSON with a version field, got %q", stdout)
	}
}

func TestMain_Doctor_NeverPanics(t *testing.T) {
	// doctor must never crash even when the environment has no
	// firewall/log-source tooling at all (true of this test sandbox).
	stdout, _, code := run("doctor")
	if code != 0 && code != 1 {
		t.Errorf("code = %d, want 0 or 1", code)
	}
	if !strings.Contains(stdout, "OS/ARCH") {
		t.Errorf("expected an OS/ARCH check line, got %q", stdout)
	}
	if !strings.Contains(stdout, "Log sources") {
		t.Errorf("expected a Log sources check line, got %q", stdout)
	}
	if !strings.Contains(stdout, "Feeds (network)") {
		t.Errorf("expected a Feeds (network) check line, got %q", stdout)
	}
}

func TestMain_Doctor_JSON(t *testing.T) {
	stdout, _, _ := run("doctor", "--json")
	if !strings.Contains(stdout, `"checks"`) {
		t.Errorf("expected JSON with a checks field, got %q", stdout)
	}
}

func TestMain_Agent_MissingSubcommand(t *testing.T) {
	_, stderr, code := run("agent")
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "missing subcommand") {
		t.Errorf("expected missing-subcommand message, got %q", stderr)
	}
}

func TestMain_Agent_UnknownSubcommand(t *testing.T) {
	_, stderr, code := run("agent", "bogus")
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr, `unknown subcommand "bogus"`) {
		t.Errorf("expected unknown-subcommand message, got %q", stderr)
	}
}

func TestMain_Agent_Enroll_MissingArgs(t *testing.T) {
	_, stderr, code := run("agent", "enroll")
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "missing <url>") {
		t.Errorf("expected a missing-URL message, got %q", stderr)
	}

	_, stderr, code = run("agent", "enroll", "https://example.com")
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "--token is required") {
		t.Errorf("expected a missing-token message, got %q", stderr)
	}
}

func TestMain_Agent_Enroll_UnreachableServer(t *testing.T) {
	dir := t.TempDir()
	_, stderr, code := run("agent", "enroll", "http://127.0.0.1:1", "--token", "t", "--data-dir", dir)
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if stderr == "" {
		t.Error("expected an error message for an unreachable server")
	}
}

func TestMain_Agent_Flush_NeverPanicsWithoutFirewallTooling(t *testing.T) {
	// On a machine (or CI sandbox) with neither nft nor iptables
	// installed, flush must fail with an actionable message, not crash.
	_, stderr, code := run("agent", "flush")
	if code != 0 && code != 1 {
		t.Errorf("code = %d, want 0 or 1", code)
	}
	if code == 1 && !strings.Contains(stderr, "breachharbor:") {
		t.Errorf("expected an actionable error prefix, got %q", stderr)
	}
}

func TestMain_Server_MissingSubcommand(t *testing.T) {
	_, stderr, code := run("server")
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "missing subcommand") {
		t.Errorf("expected missing-subcommand message, got %q", stderr)
	}
}
