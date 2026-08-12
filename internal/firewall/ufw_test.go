package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestUFW_Available_RequiresActive(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("Status: inactive\n"), nil
	}}
	b := NewUFW(fr)
	err := b.Available(context.Background())
	if err == nil {
		t.Fatal("expected an error when ufw is installed but inactive")
	}
	if !strings.Contains(err.Error(), "not active") {
		t.Errorf("error = %v, want it to mention ufw is not active", err)
	}
}

func TestUFW_Available_OKWhenActive(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("Status: active\n"), nil
	}}
	b := NewUFW(fr)
	if err := b.Available(context.Background()); err != nil {
		t.Fatalf("Available: %v", err)
	}
}

func TestUFW_Available_NoBinary(t *testing.T) {
	fr := &fakeRunner{lookPath: func(name string) (string, error) {
		return "", errors.New("not found")
	}}
	b := NewUFW(fr)
	if err := b.Available(context.Background()); err == nil {
		t.Fatal("expected an error when ufw is not on PATH")
	}
}

func TestUFW_Init_NeverEnablesUFW(t *testing.T) {
	// Regression guard: Init must never run `ufw enable` — doing so on
	// a host without its own allow rules already in place could lock
	// out SSH.
	fr := &fakeRunner{}
	b := NewUFW(fr)
	if err := b.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if len(fr.calls) != 0 {
		t.Errorf("expected Init to make no calls at all, got %+v", fr.calls)
	}
	for _, c := range fr.calls {
		if c.name == "ufw" && len(c.args) > 0 && c.args[len(c.args)-1] == "enable" {
			t.Errorf("Init must never enable ufw, got %+v", fr.calls)
		}
	}
}

func TestUFW_Block_InsertsTaggedDenyRule(t *testing.T) {
	fr := &fakeRunner{}
	b := NewUFW(fr)
	targets := []Target{
		{Addr: mustPrefix(t, "203.0.113.44/32")},
		{Addr: mustPrefix(t, "2001:db8::1/128")},
	}
	if err := b.Block(context.Background(), targets); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !containsCall(fr.calls, "ufw", "insert 1 deny from 203.0.113.44 to any comment breach-harbor") {
		t.Errorf("expected a tagged insert for the v4 target, got %+v", fr.calls)
	}
	if !containsCall(fr.calls, "ufw", "insert 1 deny from 2001:db8::1 to any comment breach-harbor") {
		t.Errorf("expected a tagged insert for the v6 target (same rule shape, no family split), got %+v", fr.calls)
	}
	for _, c := range fr.calls {
		if c.args[0] != "--force" {
			t.Errorf("expected every call to pass --force to avoid an interactive prompt, got %+v", c)
		}
	}
}

func TestUFW_Unblock_DeletesTaggedDenyRule(t *testing.T) {
	fr := &fakeRunner{}
	b := NewUFW(fr)
	targets := []Target{{Addr: mustPrefix(t, "198.51.100.9")}}
	if err := b.Unblock(context.Background(), targets); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	if !containsCall(fr.calls, "ufw", "--force delete deny from 198.51.100.9 to any comment breach-harbor") {
		t.Errorf("expected a forced, tagged delete, got %+v", fr.calls)
	}
}

func TestUFW_List_OnlyReturnsTaggedRules(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte(strings.Join([]string{
			"Added user rules (see 'ufw status' for running firewall):",
			"ufw allow 22/tcp",
			"ufw insert 1 deny from 203.0.113.44 to any comment breach-harbor",
			"ufw insert 1 deny from 198.51.100.9 to any comment breach-harbor",
			"",
		}, "\n")), nil
	}}
	b := NewUFW(fr)
	targets, err := b.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2 (the unrelated 'allow 22/tcp' rule must be ignored): %+v", len(targets), targets)
	}
}

func TestUFW_Flush_UnblocksEveryListedTarget(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "show" {
			return []byte("ufw insert 1 deny from 203.0.113.44 to any comment breach-harbor\n"), nil
		}
		return nil, nil
	}}
	b := NewUFW(fr)
	if err := b.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if !containsCall(fr.calls, "ufw", "delete deny from 203.0.113.44 to any comment breach-harbor") {
		t.Errorf("expected Flush to delete the listed target, got %+v", fr.calls)
	}
}

func TestUFW_Flush_NoopWhenNothingBlocked(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("Added user rules (see 'ufw status' for running firewall):\n"), nil
	}}
	b := NewUFW(fr)
	if err := b.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(fr.calls) != 1 {
		t.Fatalf("expected only the 'show added' listing call, got %+v", fr.calls)
	}
}

func TestUFW_Status_UsesVerboseStatus(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("Status: active\n\nTo  Action  From\n"), nil
	}}
	b := NewUFW(fr)
	out, err := b.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !strings.Contains(out, "Status: active") {
		t.Errorf("Status output = %q, want it to contain the raw ufw dump", out)
	}
	if !containsCall(fr.calls, "ufw", "status verbose") {
		t.Errorf("expected `ufw status verbose`, got %+v", fr.calls)
	}
}

func TestUFW_NeverShellsOut(t *testing.T) {
	fr := &fakeRunner{}
	b := NewUFW(fr)
	_ = b.Block(context.Background(), []Target{{Addr: mustPrefix(t, "1.2.3.4/32")}})
	for _, c := range fr.calls {
		for _, a := range c.args {
			if strings.ContainsAny(a, ";|&$`") && !strings.Contains(a, "1.2.3.4") {
				t.Errorf("unexpected shell metacharacter in argv token %q", a)
			}
		}
	}
}

func TestParseUFWShowAdded(t *testing.T) {
	out := []byte(strings.Join([]string{
		"Added user rules (see 'ufw status' for running firewall):",
		"ufw allow 22/tcp",
		"ufw insert 1 deny from 203.0.113.44 to any comment breach-harbor",
		"ufw insert 1 deny from 198.51.100.9 to any comment breach-harbor",
	}, "\n"))
	targets := parseUFWShowAdded(out)
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2: %+v", len(targets), targets)
	}
}
