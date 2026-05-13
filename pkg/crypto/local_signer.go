package crypto

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// LocalEd25519PolicySigner signs policies with a local Ed25519 private key.
type LocalEd25519PolicySigner struct {
	privateKey ed25519.PrivateKey
	keyID      string
}

// NewLocalEd25519PolicySigner generates a new random Ed25519 signer for testing.
func NewLocalEd25519PolicySigner() (PolicySigner, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return NewLocalEd25519PolicySignerFromBase64(base64.StdEncoding.EncodeToString(priv))
}

// NewLocalEd25519PolicySignerFromBase64 creates a signer from a base64-encoded
// Ed25519 private key (64 bytes seed+pub) or an OpenSSH private key PEM.
func NewLocalEd25519PolicySignerFromBase64(keyB64 string) (PolicySigner, error) {
	decoded, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("decode signing key: %w", err)
	}

	var priv ed25519.PrivateKey

	// Try raw 64-byte ed25519 private key first.
	if len(decoded) == ed25519.PrivateKeySize {
		priv = ed25519.PrivateKey(decoded)
	} else {
		// Fall back to OpenSSH PEM parsing.
		signer, err := ssh.ParseRawPrivateKey(decoded)
		if err != nil {
			return nil, fmt.Errorf("parse signing key (tried raw %d bytes and PEM): %w", len(decoded), err)
		}
		ed25519Signer, ok := signer.(ed25519.PrivateKey)
		if !ok {
			if s, ok := signer.(*ed25519.PrivateKey); ok {
				ed25519Signer = *s
			} else {
				return nil, fmt.Errorf("signing key is not ed25519")
			}
		}
		priv = ed25519Signer
	}

	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size: %d", len(priv))
	}

	keyID := os.Getenv("INTENTPROOF_POLICY_SIGNING_KEY_ID")
	if keyID == "" {
		keyID = "local:dev"
	}

	return &LocalEd25519PolicySigner{
		privateKey: priv,
		keyID:      keyID,
	}, nil
}

func (s *LocalEd25519PolicySigner) Algorithm() string { return "ed25519" }
func (s *LocalEd25519PolicySigner) KeyID() string      { return s.keyID }

func (s *LocalEd25519PolicySigner) Sign(_ context.Context, digest []byte) (*SignatureEnvelope, error) {
	sig := ed25519.Sign(s.privateKey, digest)
	return &SignatureEnvelope{
		Alg:   s.Algorithm(),
		KeyID: s.KeyID(),
		Value: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// LocalEd25519PublicKey returns the public key bytes for this signer.
func (s *LocalEd25519PolicySigner) PublicKey() []byte {
	pub := s.privateKey.Public().(ed25519.PublicKey)
	out := make([]byte, len(pub))
	copy(out, pub)
	return out
}

// DigestSHA256 computes a SHA-256 digest of the given bytes.
func DigestSHA256(data []byte) []byte {
	d := sha256.Sum256(data)
	return d[:]
}
