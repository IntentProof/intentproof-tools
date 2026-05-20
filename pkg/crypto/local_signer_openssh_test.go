package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestNewLocalEd25519PolicySignerFromOpenSSHPEM(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(pemBlock))
	signer, err := NewLocalEd25519PolicySignerFromBase64(b64)
	if err != nil {
		t.Fatal(err)
	}
	if signer.KeyID() == "" {
		t.Fatal("expected key id")
	}
}

func TestNewLocalEd25519PolicySignerUsesEnvKeyID(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_ID", "env-key")
	signer, err := NewLocalEd25519PolicySignerFromBase64(base64.StdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatal(err)
	}
	if signer.KeyID() != "env-key" {
		t.Fatalf("keyID=%s", signer.KeyID())
	}
}

func TestNewLocalEd25519PolicySignerRejectsNonEd25519PEM(t *testing.T) {
	// RSA PEM should fail the ed25519 type assertion path.
	b64 := base64.StdEncoding.EncodeToString([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n"))
	if _, err := NewLocalEd25519PolicySignerFromBase64(b64); err == nil {
		t.Fatal("expected parse error")
	}
}
