package openpgpkms

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

func TestOpenPGPValidationErrors(t *testing.T) {
	if err := ArmoredPublicKey(io.Discard, nil); err == nil {
		t.Fatal("nil entity")
	}
	if err := ArmoredDetachSign(io.Discard, nil, strings.NewReader("x"), fixedTime()); err == nil {
		t.Fatal("nil entity detach")
	}
	if err := ArmoredDetachSign(io.Discard, testEntity(t), nil, fixedTime()); err == nil {
		t.Fatal("nil message")
	}
	if err := ArmoredClearSign(io.Discard, testEntity(t), strings.NewReader("x"), time.Time{}); err == nil {
		t.Fatal("zero createdAt")
	}
	if Fingerprint(nil) != "" {
		t.Fatal("nil fingerprint")
	}
}

func TestNewEntityValidation(t *testing.T) {
	if _, err := NewEntity(nil, EntityOptions{CreatedAt: fixedTime()}); err == nil {
		t.Fatal("nil signer")
	}
	if _, err := NewEntity(badSigner{}, EntityOptions{
		Name: "n", Email: "e@x.com", CreatedAt: fixedTime(),
	}); err == nil {
		t.Fatal("bad signer public key")
	}
}

func TestSigningRoundTripWithTestEntity(t *testing.T) {
	entity := testEntity(t)
	message := []byte("Origin: IntentProof\n")
	var pub bytes.Buffer
	if err := ArmoredPublicKey(&pub, entity); err != nil {
		t.Fatal(err)
	}
	var detach bytes.Buffer
	if err := ArmoredDetachSign(&detach, entity, bytes.NewReader(message), fixedTime()); err != nil {
		t.Fatal(err)
	}
	var clear bytes.Buffer
	if err := ArmoredClearSign(&clear, entity, bytes.NewReader(message), fixedTime()); err != nil {
		t.Fatal(err)
	}
	if fp := Fingerprint(entity); fp == "" {
		t.Fatal("fingerprint")
	}
}

func TestKMSBackedSigningRoundTrip(t *testing.T) {
	_, _, entity := kmsTestEntity(t)
	message := []byte("Suite: stable\n")
	var detach bytes.Buffer
	if err := ArmoredDetachSign(&detach, entity, bytes.NewReader(message), fixedTime()); err != nil {
		t.Fatal(err)
	}
	var clear bytes.Buffer
	if err := ArmoredClearSign(&clear, entity, bytes.NewReader(message), fixedTime()); err != nil {
		t.Fatal(err)
	}
}
