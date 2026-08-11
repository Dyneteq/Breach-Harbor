package blocklist

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

// Signer is implemented server-side only — ed25519 via stdlib
// crypto/ed25519, zero new dependency.
type Signer interface {
	Sign(bl Blocklist) (signature []byte, err error)
	PublicKey() []byte
}

// Verifier is implemented agent-side (and by tests exercising the
// server's own output).
type Verifier interface {
	Verify(bl Blocklist, signature, publicKey []byte) error
}

// Ed25519Signer is the only Signer implementation — there is no
// pluggable-algorithm requirement here, unlike firewall/logsource/feed.
type Ed25519Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func GenerateKey() (*Ed25519Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Ed25519Signer{priv: priv, pub: pub}, nil
}

func (s *Ed25519Signer) Sign(bl Blocklist) ([]byte, error) {
	data, err := bl.canonical()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(s.priv, data), nil
}

func (s *Ed25519Signer) PublicKey() []byte {
	return append([]byte(nil), s.pub...)
}

// LoadOrCreateSigningKey loads an ed25519 private key from path, or
// generates and persists one at mode 0600 on first run (PLAN.md M2:
// "ed25519 key auto-generated to <data-dir>/signing.key (0600) on
// first run").
func LoadOrCreateSigningKey(path string) (*Ed25519Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("signing key at %s has unexpected length %d (want %d)", path, len(data), ed25519.PrivateKeySize)
		}
		priv := ed25519.PrivateKey(data)
		pub := priv.Public().(ed25519.PublicKey)
		return &Ed25519Signer{priv: priv, pub: pub}, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	signer, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, signer.priv, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return signer, nil
}

// ed25519Verifier is the only Verifier implementation.
type ed25519Verifier struct{}

func NewVerifier() Verifier { return ed25519Verifier{} }

func (ed25519Verifier) Verify(bl Blocklist, signature, publicKey []byte) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key length %d (want %d)", len(publicKey), ed25519.PublicKeySize)
	}
	data, err := bl.canonical()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), data, signature) {
		return fmt.Errorf("blocklist signature verification failed")
	}
	return nil
}
