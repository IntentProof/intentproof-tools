package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestNewLocalEd25519PolicySignerFromBase64Errors(t *testing.T) {
	if _, err := NewLocalEd25519PolicySignerFromBase64("%%%"); err == nil {
		t.Fatal("expected decode error")
	}
	if _, err := NewLocalEd25519PolicySignerFromBase64(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestNewLocalEd25519PolicySignerRoundTrip(t *testing.T) {
	signer, err := NewLocalEd25519PolicySigner()
	if err != nil {
		t.Fatal(err)
	}
	local, ok := signer.(*LocalEd25519PolicySigner)
	if !ok {
		t.Fatal("type")
	}
	if len(local.PublicKey()) != ed25519.PublicKeySize {
		t.Fatal("public key size")
	}
	digest := DigestSHA256([]byte("policy"))
	env, err := signer.Sign(nil, digest)
	if err != nil {
		t.Fatal(err)
	}
	if env.Alg != "ed25519" {
		t.Fatalf("alg=%s", env.Alg)
	}
}

func TestNewLocalEd25519PolicySignerFromRawSeed(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(priv)
	signer, err := NewLocalEd25519PolicySignerFromBase64(b64)
	if err != nil {
		t.Fatal(err)
	}
	if signer.KeyID() == "" {
		t.Fatal("key id")
	}
}

func TestNewKMSPolicySignerFromClientEmptyKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewKMSPolicySignerFromClient(&fakeECPolicyKMS{priv: priv}, ""); err == nil {
		t.Fatal("expected error")
	}
}
