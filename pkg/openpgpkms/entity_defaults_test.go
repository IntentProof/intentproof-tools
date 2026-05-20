package openpgpkms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestNewEntityUsesDefaults(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	entity, err := NewEntity(priv, EntityOptions{CreatedAt: fixedTime()})
	if err != nil {
		t.Fatal(err)
	}
	identity := entity.PrimaryIdentity()
	if identity == nil || !strings.Contains(identity.Name, DefaultName) {
		t.Fatalf("identity=%v", identity)
	}
}

func TestNewEntityRejectsZeroCreatedAt(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := NewEntity(priv, EntityOptions{}); err == nil {
		t.Fatal("expected creation time error")
	}
}

func TestNewEntityWithRSAPrivateKeySigner(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	entity, err := NewEntity(priv, EntityOptions{
		Name:      "Pkg",
		Email:     "pkg@example.com",
		CreatedAt: fixedTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := ArmoredPublicKey(&buf, entity); err != nil {
		t.Fatal(err)
	}
}

func TestArmoredClearSignRequiresMessage(t *testing.T) {
	entity := testEntity(t)
	if err := ArmoredClearSign(io.Discard, entity, nil, fixedTime()); err == nil {
		t.Fatal("expected error")
	}
}

func TestArmoredClearSignRejectsZeroCreatedAt(t *testing.T) {
	entity := testEntity(t)
	if err := ArmoredClearSign(io.Discard, entity, strings.NewReader("x"), time.Time{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestKMSSignerSignReportsKMSError(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewKMSSignerFromClient(context.Background(), &fakeKMSClient{
		priv:      priv,
		publicDER: der,
		signErr:   errors.New("kms down"),
	}, "alias/test")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum512([]byte("payload"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA512); err == nil {
		t.Fatal("expected sign error")
	}
}
