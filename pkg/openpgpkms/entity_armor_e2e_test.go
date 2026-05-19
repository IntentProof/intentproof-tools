package openpgpkms

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"
)

func TestNewEntityAndArmoredOutputs(t *testing.T) {
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
		Name:      "Test User",
		Email:     "test@example.com",
		CreatedAt: fixedTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var pubBuf bytes.Buffer
	if err := ArmoredPublicKey(&pubBuf, entity); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pubBuf.String(), "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Fatal("missing armor header")
	}
	msg := strings.NewReader("hello intentproof")
	var clearBuf bytes.Buffer
	if err := ArmoredClearSign(&clearBuf, entity, msg, fixedTime()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(clearBuf.String(), "BEGIN PGP SIGNED MESSAGE") {
		t.Fatal("missing clearsign header")
	}
	var detachBuf bytes.Buffer
	if err := ArmoredDetachSign(&detachBuf, entity, strings.NewReader("hello"), fixedTime()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detachBuf.String(), "BEGIN PGP SIGNATURE") {
		t.Fatal("missing detach header")
	}
}
