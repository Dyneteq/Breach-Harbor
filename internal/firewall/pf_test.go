package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPF_Init_EnablesOnlyWhenDisabled(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[0] == "-s" && args[1] == "info" {
			return []byte("Status: Disabled\n"), nil
		}
		if len(args) >= 3 && args[0] == "-a" && args[2] == "-t" {
			// -T show: table doesn't exist yet.
			return nil, errors.New("no such table")
		}
		return nil, nil
	}}
	b := NewPF(fr)
	if err := b.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !containsCall(fr.calls, "pfctl", "-e") {
		t.Errorf("expected pf to be enabled when disabled, got %+v", fr.calls)
	}
}

func TestPF_Init_DoesNotReenableWhenAlreadyEnabled(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[0] == "-s" && args[1] == "info" {
			return []byte("Status: Enabled\n"), nil
		}
		if len(args) >= 3 && args[0] == "-a" && args[2] == "-t" {
			return nil, errors.New("no such table")
		}
		return nil, nil
	}}
	b := NewPF(fr)
	if err := b.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if containsCall(fr.calls, "pfctl", "-e") {
		t.Errorf("did not expect pf to be re-enabled when already enabled, got %+v", fr.calls)
	}
}

func TestPF_Init_LoadsAnchorViaStdin(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[0] == "-s" && args[1] == "info" {
			return []byte("Status: Enabled\n"), nil
		}
		return nil, errors.New("no such table")
	}}
	b := NewPF(fr)
	if err := b.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	var loaded *call
	for i := range fr.calls {
		if fr.calls[i].name == "pfctl" && strings.Join(fr.calls[i].args, " ") == "-a breach-harbor -f -" {
			loaded = &fr.calls[i]
		}
	}
	if loaded == nil {
		t.Fatalf("expected a call loading the breach-harbor anchor via -f -, got %+v", fr.calls)
	}
	if !strings.Contains(loaded.stdin, "table <bh-blocked> persist") {
		t.Errorf("expected table declaration in stdin ruleset, got %q", loaded.stdin)
	}
	if !strings.Contains(loaded.stdin, "block in quick from <bh-blocked>") {
		t.Errorf("expected block rule in stdin ruleset, got %q", loaded.stdin)
	}
}

func TestPF_Init_IsIdempotent(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[0] == "-s" && args[1] == "info" {
			return []byte("Status: Enabled\n"), nil
		}
		// Anchor/table already loaded.
		return nil, nil
	}}
	b := NewPF(fr)
	if err := b.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if len(fr.calls) != 2 {
		t.Fatalf("expected only the status check plus the table existence check, got %d calls: %+v", len(fr.calls), fr.calls)
	}
	for _, c := range fr.calls {
		if strings.Contains(strings.Join(c.args, " "), "-f -") {
			t.Errorf("did not expect a reload when the anchor is already loaded, got %+v", fr.calls)
		}
	}
}

func TestPF_Block_UsesTableAdd(t *testing.T) {
	fr := &fakeRunner{}
	b := NewPF(fr)
	targets := []Target{
		{Addr: mustPrefix(t, "203.0.113.44/32")},
		{Addr: mustPrefix(t, "2001:db8::1/128")},
	}
	if err := b.Block(context.Background(), targets); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !containsCall(fr.calls, "pfctl", "-a breach-harbor -t bh-blocked -T add 203.0.113.44") {
		t.Errorf("expected a table add for the v4 target, got %+v", fr.calls)
	}
	if !containsCall(fr.calls, "pfctl", "-a breach-harbor -t bh-blocked -T add 2001:db8::1") {
		t.Errorf("expected a table add for the v6 target (same table, no family split), got %+v", fr.calls)
	}
}

func TestPF_Unblock_UsesTableDelete(t *testing.T) {
	fr := &fakeRunner{}
	b := NewPF(fr)
	targets := []Target{{Addr: mustPrefix(t, "198.51.100.9")}}
	if err := b.Unblock(context.Background(), targets); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	if !containsCall(fr.calls, "pfctl", "-a breach-harbor -t bh-blocked -T delete 198.51.100.9") {
		t.Errorf("expected a table delete, got %+v", fr.calls)
	}
}

func TestPF_Flush_RemovesRulesAndTableOnly(t *testing.T) {
	fr := &fakeRunner{}
	b := NewPF(fr)
	if err := b.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if !containsCall(fr.calls, "pfctl", "-a breach-harbor -F rules") {
		t.Errorf("expected rule flush scoped to the breach-harbor anchor, got %+v", fr.calls)
	}
	if !containsCall(fr.calls, "pfctl", "-a breach-harbor -t bh-blocked -T kill") {
		t.Errorf("expected table removal, got %+v", fr.calls)
	}
	for _, c := range fr.calls {
		if c.name == "pfctl" && len(c.args) > 0 && c.args[0] == "-d" {
			t.Errorf("Flush must never disable pf globally, got %+v", fr.calls)
		}
	}
}

func TestPF_Flush_NoopWhenNeverInitialized(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("no such table")
	}}
	b := NewPF(fr)
	if err := b.Flush(context.Background()); err != nil {
		t.Fatalf("Flush on never-initialized backend should be a no-op, got: %v", err)
	}
	if len(fr.calls) != 1 {
		t.Fatalf("expected only the existence check, got %+v", fr.calls)
	}
}

func TestPF_Available_NoBinary(t *testing.T) {
	fr := &fakeRunner{lookPath: func(name string) (string, error) {
		return "", errors.New("not found")
	}}
	b := NewPF(fr)
	if err := b.Available(context.Background()); err == nil {
		t.Fatal("expected an error when pfctl is not on PATH")
	}
}

func TestPF_NeverShellsOut(t *testing.T) {
	fr := &fakeRunner{}
	b := NewPF(fr)
	_ = b.Block(context.Background(), []Target{{Addr: mustPrefix(t, "1.2.3.4/32")}})
	for _, c := range fr.calls {
		for _, a := range c.args {
			if strings.ContainsAny(a, ";|&$`") && !strings.Contains(a, "1.2.3.4") {
				t.Errorf("unexpected shell metacharacter in argv token %q", a)
			}
		}
	}
}

func TestParsePFTableShow(t *testing.T) {
	out := []byte("   203.0.113.44\n198.51.100.9\n2001:db8::1\n\n")
	targets := parsePFTableShow(out)
	if len(targets) != 3 {
		t.Fatalf("got %d targets, want 3: %+v", len(targets), targets)
	}
}

func TestPF_List_EmptyWhenNeverInitialized(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("no such table")
	}}
	b := NewPF(fr)
	targets, err := b.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("expected no targets when never initialized, got %+v", targets)
	}
}
