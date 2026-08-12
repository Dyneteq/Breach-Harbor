package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestIPTablesNFT_Available_RequiresBothBinaries(t *testing.T) {
	fr := &fakeRunner{lookPath: func(name string) (string, error) {
		if name == "ip6tables-nft" {
			return "", errors.New("not found")
		}
		return "/usr/sbin/" + name, nil
	}}
	b := NewIPTablesNFT(fr)
	if err := b.Available(context.Background()); err == nil {
		t.Fatal("expected an error when ip6tables-nft is missing")
	}
}

func TestIPTablesNFT_Available_OK(t *testing.T) {
	fr := &fakeRunner{}
	b := NewIPTablesNFT(fr)
	if err := b.Available(context.Background()); err != nil {
		t.Fatalf("Available: %v", err)
	}
}

func TestIPTablesNFT_Init_CreatesDedicatedChainOnly(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && (args[0] == "-L" || args[0] == "-C") {
			return nil, errors.New("not found")
		}
		return nil, nil
	}}
	b := NewIPTablesNFT(fr)
	if err := b.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !containsCall(fr.calls, "iptables-nft", "-N BREACHHARBOR-NFT") {
		t.Errorf("expected creation of chain BREACHHARBOR-NFT, got %+v", fr.calls)
	}
	if !containsCall(fr.calls, "ip6tables-nft", "-N BREACHHARBOR-NFT6") {
		t.Errorf("expected creation of chain BREACHHARBOR-NFT6, got %+v", fr.calls)
	}
	if !containsCall(fr.calls, "iptables-nft", "-I INPUT -j BREACHHARBOR-NFT") {
		t.Errorf("expected a jump into BREACHHARBOR-NFT, got %+v", fr.calls)
	}
	// Regression guard: chain names must never collide with IPSet's own
	// (BREACHHARBOR/BREACHHARBOR6), since both could plausibly get used
	// on the same host across different agent runs.
	for _, c := range fr.calls {
		joined := strings.Join(c.args, " ")
		if strings.Contains(joined, "BREACHHARBOR") && !strings.Contains(joined, "BREACHHARBOR-NFT") {
			t.Errorf("chain name collided with IPSet's BREACHHARBOR/BREACHHARBOR6, got %+v", c)
		}
	}
}

func TestIPTablesNFT_Block_SkipsIfAlreadyPresent(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-C" {
			return nil, nil // rule already exists
		}
		return nil, nil
	}}
	b := NewIPTablesNFT(fr)
	targets := []Target{{Addr: mustPrefix(t, "203.0.113.44/32")}}
	if err := b.Block(context.Background(), targets); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if containsCall(fr.calls, "iptables-nft", "-A") {
		t.Errorf("expected no -A call when the rule already exists (idempotent), got %+v", fr.calls)
	}
}

func TestIPTablesNFT_Block_AddsDropRuleWhenMissing(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-C" {
			return nil, errors.New("no such rule")
		}
		return nil, nil
	}}
	b := NewIPTablesNFT(fr)
	targets := []Target{
		{Addr: mustPrefix(t, "203.0.113.44/32")},
		{Addr: mustPrefix(t, "2001:db8::1/128")},
	}
	if err := b.Block(context.Background(), targets); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !containsCall(fr.calls, "iptables-nft", "-A BREACHHARBOR-NFT -s 203.0.113.44 -j DROP") {
		t.Errorf("expected a DROP rule for the v4 target, got %+v", fr.calls)
	}
	if !containsCall(fr.calls, "ip6tables-nft", "-A BREACHHARBOR-NFT6 -s 2001:db8::1 -j DROP") {
		t.Errorf("expected a DROP rule for the v6 target in its own chain, got %+v", fr.calls)
	}
}

func TestIPTablesNFT_Unblock_SkipsIfAlreadyGone(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-C" {
			return nil, errors.New("no such rule")
		}
		return nil, nil
	}}
	b := NewIPTablesNFT(fr)
	targets := []Target{{Addr: mustPrefix(t, "198.51.100.9")}}
	if err := b.Unblock(context.Background(), targets); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	if containsCall(fr.calls, "iptables-nft", "-D") {
		t.Errorf("expected no -D call when the rule is already gone, got %+v", fr.calls)
	}
}

func TestIPTablesNFT_List_ParsesDropRules(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "iptables-nft" {
			return []byte("-N BREACHHARBOR-NFT\n-A BREACHHARBOR-NFT -s 203.0.113.44/32 -j DROP\n-A BREACHHARBOR-NFT -s 198.51.100.9/32 -j DROP\n"), nil
		}
		return nil, errors.New("chain not found")
	}}
	b := NewIPTablesNFT(fr)
	targets, err := b.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2: %+v", len(targets), targets)
	}
}

func TestIPTablesNFT_Flush_RemovesJumpChainOnly(t *testing.T) {
	fr := &fakeRunner{}
	b := NewIPTablesNFT(fr)
	if err := b.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if !containsCall(fr.calls, "iptables-nft", "-D INPUT -j BREACHHARBOR-NFT") {
		t.Errorf("expected jump removal, got %+v", fr.calls)
	}
	if !containsCall(fr.calls, "iptables-nft", "-X BREACHHARBOR-NFT") {
		t.Errorf("expected chain deletion, got %+v", fr.calls)
	}
	if !containsCall(fr.calls, "ip6tables-nft", "-X BREACHHARBOR-NFT6") {
		t.Errorf("expected the v6 chain to be removed too, got %+v", fr.calls)
	}
}

func TestIPTablesNFT_Flush_NoopWhenNeverInitialized(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("not found")
	}}
	b := NewIPTablesNFT(fr)
	if err := b.Flush(context.Background()); err != nil {
		t.Fatalf("Flush on never-initialized backend should be a no-op, got: %v", err)
	}
	for _, c := range fr.calls {
		if c.args[0] == "-D" || c.args[0] == "-F" || c.args[0] == "-X" {
			t.Errorf("did not expect a mutating call when nothing was ever created, got %+v", c)
		}
	}
}

func TestIPTablesNFT_Status_DumpsBothFamilies(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "iptables-nft" {
			return []byte("-P INPUT ACCEPT\n-A BREACHHARBOR-NFT -s 203.0.113.44 -j DROP\n"), nil
		}
		return nil, errors.New("no ipv6 support")
	}}
	b := NewIPTablesNFT(fr)
	out, err := b.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !strings.Contains(out, "-P INPUT ACCEPT") {
		t.Errorf("expected the iptables-nft dump in output, got %q", out)
	}
	if !strings.Contains(out, "unavailable") {
		t.Errorf("expected the ip6tables-nft failure to be noted inline, got %q", out)
	}
}

func TestIPTablesNFT_NeverShellsOut(t *testing.T) {
	fr := &fakeRunner{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("no such rule") // force the -A path in Block
	}}
	b := NewIPTablesNFT(fr)
	_ = b.Block(context.Background(), []Target{{Addr: mustPrefix(t, "1.2.3.4/32")}})
	for _, c := range fr.calls {
		for _, a := range c.args {
			if strings.ContainsAny(a, ";|&$`") && !strings.Contains(a, "1.2.3.4") {
				t.Errorf("unexpected shell metacharacter in argv token %q", a)
			}
		}
	}
}

func TestParseIPTablesDropRules(t *testing.T) {
	out := []byte("-N BREACHHARBOR-NFT\n-A BREACHHARBOR-NFT -s 203.0.113.44/32 -j DROP\n-A BREACHHARBOR-NFT -s 198.51.100.9/32 -j DROP\n-A OTHERCHAIN -s 10.0.0.1/32 -j ACCEPT\n")
	targets := parseIPTablesDropRules(out)
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2 (non-DROP/other-chain lines must be ignored): %+v", len(targets), targets)
	}
}
