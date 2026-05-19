package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestVerifyEd25519InvalidSignatureBytes(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env := &SignatureEnvelope{Alg: "ed25519", Value: base64.StdEncoding.EncodeToString([]byte{1})}
	pub := priv.Public().(ed25519.PublicKey)
	if err := NewPolicySignatureVerifier().Verify([]byte("x"), env, pub); err == nil {
		t.Fatal("expected verify failure")
	}
}

func TestParseEd25519PublicKeyInvalidPEM(t *testing.T) {
	if _, err := ParseEd25519PublicKey([]byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----")); err == nil {
		t.Fatal("expected error")
	}
}
