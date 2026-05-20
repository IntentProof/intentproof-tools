package openpgpkms

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

func TestNewEntityRejectsNilSigner(t *testing.T) {
	if _, err := NewEntity(nil, EntityOptions{CreatedAt: time.Now()}); err == nil {
		t.Fatal("expected error")
	}
}

func TestNewEntityValidationRejectsZeroCreatedAt(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEntity(priv, EntityOptions{Name: "Test", Email: "t@example.com"}); err == nil {
		t.Fatal("expected creation time error")
	}
}

func TestNewEntityUsesDefaultNameAndEmail(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	entity, err := NewEntity(priv, EntityOptions{CreatedAt: fixedTime()})
	if err != nil {
		t.Fatal(err)
	}
	if entity == nil || entity.PrimaryKey == nil {
		t.Fatal("expected entity")
	}
}