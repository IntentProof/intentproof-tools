package openpgpkms

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestArmoredPublicKeyRejectsNilEntity(t *testing.T) {
	if err := ArmoredPublicKey(failWriter{}, nil); err == nil {
		t.Fatal("expected nil entity error")
	} else if !strings.Contains(err.Error(), "entity is required") {
		t.Fatalf("err=%v", err)
	}
}

func TestNewEntityRejectsInvalidUserIDComponents(t *testing.T) {
	priv := testRSAPrivateKey(t)
	_, err := NewEntity(priv, EntityOptions{
		Name: "\x00", Email: "\x00", CreatedAt: fixedTime(),
	})
	if err == nil || !strings.Contains(err.Error(), "invalid OpenPGP user ID") {
		t.Fatalf("err=%v", err)
	}
}

func testRSAPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}
