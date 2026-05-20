package openpgpkms

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

func TestVerifyAptMetadataReaderErrors(t *testing.T) {
	entity := testEntity(t)
	message := []byte("Origin: IntentProof\n")
	createdAt := fixedTime()

	var publicKey bytes.Buffer
	if err := ArmoredPublicKey(&publicKey, entity); err != nil {
		t.Fatal(err)
	}
	var releaseSig bytes.Buffer
	if err := ArmoredDetachSign(&releaseSig, entity, bytes.NewReader(message), createdAt); err != nil {
		t.Fatal(err)
	}
	var inrelease bytes.Buffer
	if err := ArmoredClearSign(&inrelease, entity, bytes.NewReader(message), createdAt); err != nil {
		t.Fatal(err)
	}

	if err := VerifyAptMetadata(errReader{err: errors.New("key read")}, bytes.NewReader(message),
		bytes.NewReader(releaseSig.Bytes()), bytes.NewReader(inrelease.Bytes())); err == nil ||
		!strings.Contains(err.Error(), "read armored public key") {
		t.Fatalf("key err=%v", err)
	}

	if err := VerifyAptMetadata(bytes.NewReader(publicKey.Bytes()), errReader{err: errors.New("release read")},
		bytes.NewReader(releaseSig.Bytes()), bytes.NewReader(inrelease.Bytes())); err == nil ||
		!strings.Contains(err.Error(), "read release") {
		t.Fatalf("release err=%v", err)
	}

	if err := VerifyAptMetadata(bytes.NewReader(publicKey.Bytes()), bytes.NewReader(message),
		bytes.NewReader(releaseSig.Bytes()), errReader{err: errors.New("inrelease read")}); err == nil ||
		!strings.Contains(err.Error(), "read InRelease") {
		t.Fatalf("inrelease err=%v", err)
	}
}

func TestVerifyAptMetadataRejectsInvalidClearsign(t *testing.T) {
	entity := testEntity(t)
	message := []byte("Origin: IntentProof\n")
	createdAt := fixedTime()

	var publicKey bytes.Buffer
	if err := ArmoredPublicKey(&publicKey, entity); err != nil {
		t.Fatal(err)
	}
	var releaseSig bytes.Buffer
	if err := ArmoredDetachSign(&releaseSig, entity, bytes.NewReader(message), createdAt); err != nil {
		t.Fatal(err)
	}

	err := VerifyAptMetadata(bytes.NewReader(publicKey.Bytes()), bytes.NewReader(message),
		bytes.NewReader(releaseSig.Bytes()), bytes.NewReader([]byte("not clearsigned")))
	if err == nil || !strings.Contains(err.Error(), "decode clearsigned") {
		t.Fatalf("err=%v", err)
	}
}

func TestVerifyAptMetadataRejectsBadDetachedSignature(t *testing.T) {
	entity := testEntity(t)
	message := []byte("Origin: IntentProof\n")
	createdAt := fixedTime()

	var publicKey bytes.Buffer
	if err := ArmoredPublicKey(&publicKey, entity); err != nil {
		t.Fatal(err)
	}
	var inrelease bytes.Buffer
	if err := ArmoredClearSign(&inrelease, entity, bytes.NewReader(message), createdAt); err != nil {
		t.Fatal(err)
	}

	err := VerifyAptMetadata(bytes.NewReader(publicKey.Bytes()), bytes.NewReader(message),
		bytes.NewReader([]byte("-----BEGIN PGP SIGNATURE-----\ninvalid\n-----END PGP SIGNATURE-----\n")),
		bytes.NewReader(inrelease.Bytes()))
	if err == nil || !strings.Contains(err.Error(), "verify Release.gpg") {
		t.Fatalf("err=%v", err)
	}
}

func TestVerifyAptMetadataFilesMissingSignatureAndInRelease(t *testing.T) {
	artifacts := writePackageSigningArtifacts(t, "ipaptfiles-*")
	if err := VerifyAptMetadataFiles(artifacts.keyPath, artifacts.messagePath, "/no/sig", artifacts.messagePath); err == nil ||
		!strings.Contains(err.Error(), "open Release.gpg") {
		t.Fatalf("sig err=%v", err)
	}
	if err := VerifyAptMetadataFiles(artifacts.keyPath, artifacts.messagePath, artifacts.sigPath, "/no/inrelease"); err == nil ||
		!strings.Contains(err.Error(), "open InRelease") {
		t.Fatalf("inrelease err=%v", err)
	}
}

func TestVerifyAptMetadataRejectsMissingReleaseInputs(t *testing.T) {
	if err := VerifyAptMetadata(bytes.NewReader([]byte("x")), nil,
		bytes.NewReader([]byte("y")), bytes.NewReader([]byte("z"))); err == nil {
		t.Fatal("expected error")
	}
	if err := VerifyAptMetadata(io.NopCloser(bytes.NewReader([]byte("not a key"))),
		bytes.NewReader([]byte("release")), bytes.NewReader([]byte("sig")),
		bytes.NewReader([]byte("inrelease"))); err == nil ||
		!strings.Contains(err.Error(), "read armored public key") {
		t.Fatalf("err=%v", err)
	}
}
