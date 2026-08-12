package blocklist

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func testBlocklist() Blocklist {
	return Blocklist{
		Version:     1,
		GeneratedAt: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC),
		TTL:         30 * time.Minute,
		Entries: []Entry{
			{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Reason: "spamhaus DROP"},
			{Prefix: netip.MustParsePrefix("198.51.100.44/32"), Reason: "tor exit node"},
		},
	}
}

func TestSignAndVerify_RoundTrip(t *testing.T) {
	signer, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	bl := testBlocklist()

	sig, err := signer.Sign(bl)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := NewVerifier().Verify(bl, sig, signer.PublicKey()); err != nil {
		t.Errorf("Verify: expected success, got %v", err)
	}
}

func TestVerify_RejectsTamperedBlocklist(t *testing.T) {
	signer, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	bl := testBlocklist()
	sig, err := signer.Sign(bl)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tampered := bl
	tampered.Entries = append(tampered.Entries, Entry{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Reason: "injected"})

	if err := NewVerifier().Verify(tampered, sig, signer.PublicKey()); err == nil {
		t.Error("expected verification of a tampered blocklist to fail, got nil error")
	}
}

func TestVerify_RejectsWrongPublicKey(t *testing.T) {
	signer, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	other, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	bl := testBlocklist()
	sig, err := signer.Sign(bl)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := NewVerifier().Verify(bl, sig, other.PublicKey()); err == nil {
		t.Error("expected verification against the wrong public key to fail, got nil error")
	}
}

func TestLoadOrCreateSigningKey_PersistsAndReuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.key")

	first, err := LoadOrCreateSigningKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKey (create): %v", err)
	}

	second, err := LoadOrCreateSigningKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKey (reload): %v", err)
	}

	if string(first.PublicKey()) != string(second.PublicKey()) {
		t.Error("expected the same public key across reloads of the same signing key file")
	}
}

func TestPublisher_ServesLastGoodOnSourceError(t *testing.T) {
	signer, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	calls := 0
	source := func(ctx context.Context) ([]Entry, error) {
		calls++
		if calls == 1 {
			return []Entry{{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Reason: "first"}}, nil
		}
		return nil, context.DeadlineExceeded
	}

	pub := NewPublisher(signer, source, time.Hour, 30*time.Minute)
	pub.refresh(context.Background())
	first, ok := pub.Current()
	if !ok {
		t.Fatal("expected a published blocklist after the first successful refresh")
	}
	if len(first.Blocklist.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(first.Blocklist.Entries))
	}

	pub.refresh(context.Background()) // source now errors
	second, ok := pub.Current()
	if !ok {
		t.Fatal("expected Current to still report the last-good blocklist")
	}
	if second.Blocklist.Version != first.Blocklist.Version {
		t.Errorf("version changed on a failed refresh: %d -> %d", first.Blocklist.Version, second.Blocklist.Version)
	}
}

func TestMerge_UnionsAndDedupesByPrefix(t *testing.T) {
	local := []Entry{
		{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Reason: "local: ssh brute force"},
	}
	fromServer := []Entry{
		{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Reason: "server: consensus"},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Reason: "server: spamhaus"},
	}

	merged := Merge(local, fromServer)
	if len(merged) != 2 {
		t.Fatalf("expected 2 deduped entries, got %d: %+v", len(merged), merged)
	}
	// Local entry wins on a duplicate prefix — Merge appends local
	// first and dedupes on first-seen.
	if merged[0].Reason != "local: ssh brute force" {
		t.Errorf("expected the local entry to win the dedupe, got %q", merged[0].Reason)
	}
}
