package crypto

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestNewLocalEd25519PolicySignerFromBase64RawKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(priv)
	signer, err := NewLocalEd25519PolicySignerFromBase64(b64)
	if err != nil {
		t.Fatal(err)
	}
	env, err := signer.Sign(context.Background(), DigestSHA256([]byte("policy")))
	if err != nil {
		t.Fatal(err)
	}
	if env.KeyID == "" {
		t.Fatal("key id")
	}
}

func TestNewLocalEd25519PolicySignerFromBase64Invalid(t *testing.T) {
	if _, err := NewLocalEd25519PolicySignerFromBase64("%%%"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestLocalEd25519PublicKeyCopy(t *testing.T) {
	signer, err := NewLocalEd25519PolicySigner()
	if err != nil {
		t.Fatal(err)
	}
	ls := signer.(*LocalEd25519PolicySigner)
	pub := ls.PublicKey()
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("len=%d", len(pub))
	}
}
