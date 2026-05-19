package openpgpkms

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyAptMetadata(t *testing.T) {
	entity := testEntity(t)
	message := []byte("Origin: IntentProof\nSuite: stable\n")
	createdAt := fixedTime()

	var publicKey bytes.Buffer
	if err := ArmoredPublicKey(&publicKey, entity); err != nil {
		t.Fatalf("export public key: %v", err)
	}
	var releaseSig bytes.Buffer
	if err := ArmoredDetachSign(&releaseSig, entity, bytes.NewReader(message), createdAt); err != nil {
		t.Fatalf("detach sign: %v", err)
	}
	var inrelease bytes.Buffer
	if err := ArmoredClearSign(&inrelease, entity, bytes.NewReader(message), createdAt); err != nil {
		t.Fatalf("clear sign: %v", err)
	}
	if err := VerifyAptMetadata(bytes.NewReader(publicKey.Bytes()), bytes.NewReader(message), bytes.NewReader(releaseSig.Bytes()), bytes.NewReader(inrelease.Bytes())); err != nil {
		t.Fatalf("verify apt metadata: %v", err)
	}
}

func TestVerifyAptMetadataRejectsMismatchedRelease(t *testing.T) {
	entity := testEntity(t)
	createdAt := fixedTime()
	message := []byte("Origin: IntentProof\nSuite: stable\n")
	other := []byte("Origin: IntentProof\nSuite: other\n")

	var publicKey bytes.Buffer
	if err := ArmoredPublicKey(&publicKey, entity); err != nil {
		t.Fatalf("export public key: %v", err)
	}
	var releaseSig bytes.Buffer
	if err := ArmoredDetachSign(&releaseSig, entity, bytes.NewReader(message), createdAt); err != nil {
		t.Fatalf("detach sign: %v", err)
	}
	var inrelease bytes.Buffer
	if err := ArmoredClearSign(&inrelease, entity, bytes.NewReader(other), createdAt); err != nil {
		t.Fatalf("clear sign: %v", err)
	}
	if err := VerifyAptMetadata(bytes.NewReader(publicKey.Bytes()), bytes.NewReader(message), bytes.NewReader(releaseSig.Bytes()), bytes.NewReader(inrelease.Bytes())); err == nil {
		t.Fatal("expected mismatched InRelease to fail verification")
	}
}

func TestKMSSignerVerifyAptMetadata(t *testing.T) {
	priv, kmsSigner, entity := kmsTestEntity(t)
	_ = priv
	message := []byte("Origin: IntentProof\nSuite: stable\n")
	createdAt := fixedTime()

	var publicKey bytes.Buffer
	if err := ArmoredPublicKey(&publicKey, entity); err != nil {
		t.Fatalf("export public key: %v", err)
	}
	var releaseSig bytes.Buffer
	if err := ArmoredDetachSign(&releaseSig, entity, bytes.NewReader(message), createdAt); err != nil {
		t.Fatalf("detach sign: %v", err)
	}
	var inrelease bytes.Buffer
	if err := ArmoredClearSign(&inrelease, entity, bytes.NewReader(message), createdAt); err != nil {
		t.Fatalf("clear sign: %v", err)
	}
	if err := VerifyAptMetadata(bytes.NewReader(publicKey.Bytes()), bytes.NewReader(message), bytes.NewReader(releaseSig.Bytes()), bytes.NewReader(inrelease.Bytes())); err != nil {
		t.Fatalf("verify kms-backed apt metadata: %v", err)
	}
	_ = kmsSigner
}

func TestVerifyAptMetadataWithReleaseLayout(t *testing.T) {
	entity := testEntity(t)
	releaseBytes, err := os.ReadFile("testdata/apt-stable-Release")
	if err != nil {
		t.Fatalf("read testdata release: %v", err)
	}
	createdAt := fixedTime()

	var publicKey bytes.Buffer
	if err := ArmoredPublicKey(&publicKey, entity); err != nil {
		t.Fatalf("export public key: %v", err)
	}
	var releaseSig bytes.Buffer
	if err := ArmoredDetachSign(&releaseSig, entity, bytes.NewReader(releaseBytes), createdAt); err != nil {
		t.Fatalf("detach sign: %v", err)
	}
	var inrelease bytes.Buffer
	if err := ArmoredClearSign(&inrelease, entity, bytes.NewReader(releaseBytes), createdAt); err != nil {
		t.Fatalf("clear sign: %v", err)
	}
	if err := VerifyAptMetadata(bytes.NewReader(publicKey.Bytes()), bytes.NewReader(releaseBytes), bytes.NewReader(releaseSig.Bytes()), bytes.NewReader(inrelease.Bytes())); err != nil {
		t.Fatalf("verify apt metadata with release layout: %v", err)
	}
}

func TestVerifyAptMetadataFiles(t *testing.T) {
	entity := testEntity(t)
	dir := t.TempDir()
	message := []byte("Origin: IntentProof\nSuite: stable\n")
	createdAt := fixedTime()

	publicKeyPath := filepath.Join(dir, "intentproof.gpg")
	releasePath := filepath.Join(dir, "Release")
	releaseSigPath := filepath.Join(dir, "Release.gpg")
	inreleasePath := filepath.Join(dir, "InRelease")
	if err := os.WriteFile(releasePath, message, 0o644); err != nil {
		t.Fatalf("write release: %v", err)
	}
	var publicKey bytes.Buffer
	if err := ArmoredPublicKey(&publicKey, entity); err != nil {
		t.Fatalf("export public key: %v", err)
	}
	if err := os.WriteFile(publicKeyPath, publicKey.Bytes(), 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	var releaseSig bytes.Buffer
	if err := ArmoredDetachSign(&releaseSig, entity, bytes.NewReader(message), createdAt); err != nil {
		t.Fatalf("detach sign: %v", err)
	}
	if err := os.WriteFile(releaseSigPath, releaseSig.Bytes(), 0o644); err != nil {
		t.Fatalf("write release signature: %v", err)
	}
	var inrelease bytes.Buffer
	if err := ArmoredClearSign(&inrelease, entity, bytes.NewReader(message), createdAt); err != nil {
		t.Fatalf("clear sign: %v", err)
	}
	if err := os.WriteFile(inreleasePath, inrelease.Bytes(), 0o644); err != nil {
		t.Fatalf("write inrelease: %v", err)
	}
	if err := VerifyAptMetadataFiles(publicKeyPath, releasePath, releaseSigPath, inreleasePath); err != nil {
		t.Fatalf("verify apt metadata files: %v", err)
	}
}
