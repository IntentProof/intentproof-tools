package openpgpkms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestNewKMSSignerRejectsEmptyKeyID(t *testing.T) {
	if _, err := NewKMSSigner(context.Background(), ""); err == nil {
		t.Fatal("expected error")
	}
	if _, err := NewKMSSigner(nil, "   "); err == nil {
		t.Fatal("expected error for whitespace key")
	}
}

func TestNewKMSSignerFromClientNilContext(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeKMSClient{priv: priv, publicDER: publicDER}
	signer, err := NewKMSSignerFromClient(nil, client, "alias/test")
	if err != nil {
		t.Fatal(err)
	}
	if signer == nil || signer.Public() == nil {
		t.Fatal("expected signer")
	}
}
