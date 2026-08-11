package firewall

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// call records one invocation made through the runner seam.
type call struct {
	name string
	args []string
}

// fakeRunner is a scriptable runner used to assert the exact argv a
// backend issues, without touching a real nft/iptables/ipset binary.
type fakeRunner struct {
	lookPath func(name string) (string, error)
	run      func(ctx context.Context, name string, args ...string) ([]byte, error)
	calls    []call
}

func (f *fakeRunner) LookPath(name string) (string, error) {
	if f.lookPath != nil {
		return f.lookPath(name)
	}
	return "/usr/sbin/" + name, nil
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, call{name: name, args: append([]string(nil), args...)})
	if f.run != nil {
		return f.run(ctx, name, args...)
	}
	return nil, nil
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if aerr != nil {
			t.Fatalf("invalid address %q: %v", s, err)
		}
		return netip.PrefixFrom(a, a.BitLen())
	}
	return p
}

func containsCall(calls []call, name string, argSubstr string) bool {
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

func TestNFTables_Init_CreatesDedicatedTableOnly(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "nft" && len(args) >= 3 && args[0] == "list" && args[1] == "table" {
			return nil, errors.New("no such table")
		}
		return nil, nil
	}}
	b := NewNFTables(fr)
	if err := b.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !containsCall(fr.calls, "nft", "add table inet breachharbor") {
		t.Errorf("expected a call creating table inet breachharbor, got %+v", fr.calls)
	}
	for _, c := range fr.calls {
		joined := strings.Join(c.args, " ")
		if strings.Contains(joined, "table") && !strings.Contains(joined, "breachharbor") {
			t.Errorf("nft call touched something outside the breachharbor table: %+v", c)
		}
	}
}

func TestNFTables_Init_IsIdempotent(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		// Table already exists.
		return nil, nil
	}}
	b := NewNFTables(fr)
	if err := b.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if len(fr.calls) != 1 {
		t.Fatalf("expected only the existence check when table already exists, got %d calls: %+v", len(fr.calls), fr.calls)
	}
}

func TestNFTables_Block_SplitsByFamily(t *testing.T) {
	fr := &fakeRunner{}
	b := NewNFTables(fr)
	targets := []Target{
		{Addr: mustPrefix(t, "203.0.113.44/32")},
		{Addr: mustPrefix(t, "2001:db8::1/128")},
	}
	if err := b.Block(context.Background(), targets); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !containsCall(fr.calls, "nft", "blocked4") {
		t.Errorf("expected a call touching blocked4 for the v4 target, got %+v", fr.calls)
	}
	if !containsCall(fr.calls, "nft", "blocked6") {
		t.Errorf("expected a call touching blocked6 for the v6 target, got %+v", fr.calls)
	}
	if !containsCall(fr.calls, "nft", "203.0.113.44") {
		t.Errorf("expected the v4 address in argv, got %+v", fr.calls)
	}
}

func TestNFTables_Flush_DeletesTableOnly(t *testing.T) {
	fr := &fakeRunner{}
	b := NewNFTables(fr)
	if err := b.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(fr.calls) != 2 {
		t.Fatalf("expected an existence check plus one delete call, got %+v", fr.calls)
	}
	last := fr.calls[len(fr.calls)-1]
	want := []string{"delete", "table", "inet", "breachharbor"}
	if strings.Join(last.args, " ") != strings.Join(want, " ") {
		t.Errorf("flush args = %v, want %v", last.args, want)
	}
}

func TestNFTables_Flush_NoopWhenNeverInitialized(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("no such table")
	}}
	b := NewNFTables(fr)
	if err := b.Flush(context.Background()); err != nil {
		t.Fatalf("Flush on never-initialized backend should be a no-op, got: %v", err)
	}
	if len(fr.calls) != 1 {
		t.Fatalf("expected only the existence check, got %+v", fr.calls)
	}
}

func TestNFTables_Available_NoBinary(t *testing.T) {
	fr := &fakeRunner{lookPath: func(name string) (string, error) {
		return "", errors.New("not found")
	}}
	b := NewNFTables(fr)
	if err := b.Available(context.Background()); err == nil {
		t.Fatal("expected an error when nft is not on PATH")
	}
}

func TestNFTables_NeverShellsOut(t *testing.T) {
	// Regression guard: every argv element must be a discrete token,
	// never a single string containing shell metacharacters intended
	// for interpretation (e.g. "; rm -rf /").
	fr := &fakeRunner{}
	b := NewNFTables(fr)
	evil := "1.2.3.4/32"
	_ = b.Block(context.Background(), []Target{{Addr: mustPrefix(t, evil)}})
	for _, c := range fr.calls {
		for _, a := range c.args {
			if strings.ContainsAny(a, ";|&$`") && !strings.Contains(a, "1.2.3.4") {
				t.Errorf("unexpected shell metacharacter in argv token %q", a)
			}
		}
	}
}

func TestIPSet_Init_CreatesDedicatedResourcesOnly(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		// Everything reports "does not exist yet" so Init does its full job.
		if len(args) > 0 && (args[0] == "list" || args[0] == "-L" || args[0] == "-C") {
			return nil, errors.New("not found")
		}
		return nil, nil
	}}
	b := NewIPSet(fr)
	if err := b.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !containsCall(fr.calls, "ipset", "create bh-blocked4") {
		t.Errorf("expected creation of bh-blocked4, got %+v", fr.calls)
	}
	if !containsCall(fr.calls, "ipset", "create bh-blocked6") {
		t.Errorf("expected creation of bh-blocked6, got %+v", fr.calls)
	}
	if !containsCall(fr.calls, "iptables", "-N BREACHHARBOR") {
		t.Errorf("expected creation of chain BREACHHARBOR, got %+v", fr.calls)
	}
	if !containsCall(fr.calls, "ip6tables", "-N BREACHHARBOR6") {
		t.Errorf("expected creation of chain BREACHHARBOR6, got %+v", fr.calls)
	}
}

func TestIPSet_Block_UsesExistFlag(t *testing.T) {
	fr := &fakeRunner{}
	b := NewIPSet(fr)
	targets := []Target{{Addr: mustPrefix(t, "198.51.100.9")}}
	if err := b.Block(context.Background(), targets); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !containsCall(fr.calls, "ipset", "add bh-blocked4 198.51.100.9 -exist") {
		t.Errorf("expected idempotent -exist add, got %+v", fr.calls)
	}
}

func TestIPSet_Flush_RemovesJumpChainAndSet(t *testing.T) {
	fr := &fakeRunner{}
	b := NewIPSet(fr)
	if err := b.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if !containsCall(fr.calls, "iptables", "-D INPUT -j BREACHHARBOR") {
		t.Errorf("expected jump removal, got %+v", fr.calls)
	}
	if !containsCall(fr.calls, "iptables", "-X BREACHHARBOR") {
		t.Errorf("expected chain deletion, got %+v", fr.calls)
	}
	if !containsCall(fr.calls, "ipset", "destroy bh-blocked4") {
		t.Errorf("expected set destruction, got %+v", fr.calls)
	}
}

func TestParseNFTSetElements(t *testing.T) {
	out := []byte(`table inet breachharbor {
	set blocked4 {
		type ipv4_addr
		flags interval
		elements = { 203.0.113.44, 198.51.100.9 }
	}
}`)
	targets := parseNFTSetElements(out)
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2: %+v", len(targets), targets)
	}
}

func TestParseIPSetSave(t *testing.T) {
	out := []byte("create bh-blocked4 hash:ip family inet\nadd bh-blocked4 203.0.113.44\nadd bh-blocked4 198.51.100.9\n")
	targets := parseIPSetSave("bh-blocked4", out)
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2: %+v", len(targets), targets)
	}
}

func TestDetect_UnknownBackend(t *testing.T) {
	if _, err := Detect(context.Background(), "bogus"); err == nil {
		t.Fatal("expected an error for an unknown backend name")
	}
}

func TestDetect_NoneAvailable(t *testing.T) {
	// Detect uses the real execRunner internally for its candidates, so
	// on a machine with neither nft nor iptables (or in a sandboxed
	// test environment) it must return a clear error, not panic.
	_, err := Detect(context.Background(), "auto")
	if err != nil && !strings.Contains(err.Error(), "no usable firewall backend") {
		t.Errorf("unexpected error shape: %v", err)
	}
}
