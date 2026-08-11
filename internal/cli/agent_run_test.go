package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/store"
)

// These call runAgentRun directly (rather than through Main, which
// owns a real signal.NotifyContext) so the test controls exactly when
// the run loop stops, via an ordinary context.WithTimeout — Agent.Run
// returns as soon as ctx is cancelled (internal/agent/agent_test.go
// covers its internal behavior in detail; these just confirm the CLI
// wiring: flags, banner, and clean shutdown).

func TestRunAgentRun_ExitsPromptlyOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	var out, errBuf bytes.Buffer
	code := runAgentRun(ctx, []string{"--data-dir", dir}, &out, &errBuf)
	if code != 0 {
		t.Errorf("code = %d, want 0 (clean shutdown on context cancel); stderr=%q", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "BREACH::HARBOR agent") {
		t.Errorf("expected the startup banner, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "DRY RUN") {
		t.Errorf("expected the dry-run banner by default, got:\n%s", out.String())
	}
}

func TestRunAgentRun_JSON_SkipsHumanBanner(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	var out, errBuf bytes.Buffer
	code := runAgentRun(ctx, []string{"--data-dir", dir, "--json"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("code = %d, want 0; stderr=%q", code, errBuf.String())
	}
	if strings.Contains(out.String(), "DRY RUN — nothing") {
		t.Errorf("expected --json to skip the human banner box, got:\n%s", out.String())
	}
}

func TestRunAgentRun_InvalidFlags_ExitsWithoutEnteringTheLoop(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runAgentRun(context.Background(), []string{"--data-dir", dir, "--firewall", "bogus"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
}

func TestRunAgentRun_ConfigFlagNotImplemented(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runAgentRun(context.Background(), []string{"--config", "/tmp/x.yaml"}, &out, &errBuf)
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if !strings.Contains(errBuf.String(), "not implemented") {
		t.Errorf("expected a not-implemented message, got %q", errBuf.String())
	}
}

func TestRunAgentRun_LockContention_ExitsCleanly(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	var out, errBuf bytes.Buffer
	code := runAgentRun(context.Background(), []string{"--data-dir", dir}, &out, &errBuf)
	if code != 1 {
		t.Errorf("code = %d, want 1 (lock already held by the store opened above)", code)
	}
}

func TestParseFeedFlag(t *testing.T) {
	cases := []struct {
		raw  string
		want map[string]bool
	}{
		{"", nil},
		{"spamhaus=off", map[string]bool{"spamhaus": false}},
		{"spamhaus=off,tor=on", map[string]bool{"spamhaus": false, "tor": true}},
		{"garbage", map[string]bool{}},
	}
	for _, c := range cases {
		got := parseFeedFlag(c.raw)
		if len(got) != len(c.want) {
			t.Errorf("parseFeedFlag(%q) = %v, want %v", c.raw, got, c.want)
			continue
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("parseFeedFlag(%q)[%q] = %v, want %v", c.raw, k, got[k], v)
			}
		}
	}
}
