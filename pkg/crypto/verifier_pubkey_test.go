package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestParseEd25519PublicKeyFromPEM(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	pemBytes := pem.EncodeToMemory(block)
	parsed, err := ParseEd25519PublicKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != ed25519.PublicKeySize {
		t.Fatalf("len=%d", len(parsed))
	}
}

func TestParseEd25519PublicKeyRaw32(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	parsed, err := ParseEd25519PublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != ed25519.PublicKeySize {
		t.Fatalf("len=%d", len(parsed))
	}
}

func TestNewPolicySignatureVerifierRejectsNilKey(t *testing.T) {
	v := NewPolicySignatureVerifier()
	env := &SignatureEnvelope{Alg: "ed25519", Value: "AAAA"}
	if err := v.Verify([]byte("x"), env, nil); err == nil {
		t.Fatal("expected error")
	}
}
