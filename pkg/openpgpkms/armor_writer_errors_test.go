package openpgpkms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
)

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestArmoredPublicKeyWriteError(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	entity, err := NewEntity(priv, EntityOptions{
		Name: "Test", Email: "t@example.com", CreatedAt: fixedTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ArmoredPublicKey(failWriter{}, entity); err == nil {
		t.Fatal("expected write error")
	}
}

func TestArmoredClearSignWriteError(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	entity, err := NewEntity(priv, EntityOptions{
		Name: "Test", Email: "t@example.com", CreatedAt: fixedTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ArmoredClearSign(failWriter{}, entity, strings.NewReader("msg"), fixedTime()); err == nil {
		t.Fatal("expected write error")
	}
}

func TestArmoredDetachSignWriteError(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeKMSClient{priv: priv, publicDER: publicDER}
	signer, err := NewKMSSignerFromClient(context.Background(), client, "alias/test")
	if err != nil {
		t.Fatal(err)
	}
	entity, err := NewEntity(signer, EntityOptions{
		Name: "Test", Email: "t@example.com", CreatedAt: fixedTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ArmoredDetachSign(failWriter{}, entity, strings.NewReader("x"), fixedTime()); err == nil {
		t.Fatal("expected write error")
	}
}
