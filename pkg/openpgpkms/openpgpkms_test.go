package openpgpkms

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/openpgp"
)

func TestArmoredDetachSignVerifiesWithOpenPGP(t *testing.T) {
	entity := testEntity(t)
	message := []byte("intentproof package repository metadata\n")

	var publicKey bytes.Buffer
	if err := ArmoredPublicKey(&publicKey, entity); err != nil {
		t.Fatalf("export public key: %v", err)
	}
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(publicKey.Bytes()))
	if err != nil {
		t.Fatalf("read armored keyring: %v", err)
	}

	var sig bytes.Buffer
	if err := ArmoredDetachSign(&sig, entity, bytes.NewReader(message), fixedTime()); err != nil {
		t.Fatalf("detach sign: %v", err)
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(message), bytes.NewReader(sig.Bytes())); err != nil {
		t.Fatalf("verify detached signature: %v", err)
	}
}

func TestArmoredDetachSignVerifiesWithGPGWhenAvailable(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	entity := testEntity(t)
	dir, err := os.MkdirTemp("/tmp", "ipgpg-*")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	defer os.RemoveAll(dir)
	messagePath := filepath.Join(dir, "Release")
	keyPath := filepath.Join(dir, "intentproof.gpg")
	sigPath := filepath.Join(dir, "Release.gpg")
	home := filepath.Join(dir, "gnupg")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatalf("mkdir gnupg home: %v", err)
	}
	message := []byte("Origin: IntentProof\nSuite: stable\n")
	if err := os.WriteFile(messagePath, message, 0o644); err != nil {
		t.Fatalf("write message: %v", err)
	}

	var publicKey bytes.Buffer
	if err := ArmoredPublicKey(&publicKey, entity); err != nil {
		t.Fatalf("export public key: %v", err)
	}
	if err := os.WriteFile(keyPath, publicKey.Bytes(), 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	var sig bytes.Buffer
	if err := ArmoredDetachSign(&sig, entity, bytes.NewReader(message), fixedTime()); err != nil {
		t.Fatalf("detach sign: %v", err)
	}
	if err := os.WriteFile(sigPath, sig.Bytes(), 0o644); err != nil {
		t.Fatalf("write signature: %v", err)
	}

	runGPG(t, home, "--import", keyPath)
	runGPG(t, home, "--verify", sigPath, messagePath)
}

func TestRejectsNonRSASigner(t *testing.T) {
	_, err := NewEntity(badSigner{}, EntityOptions{CreatedAt: fixedTime()})
	if err == nil {
		t.Fatal("expected non-RSA signer to fail")
	}
}

func testEntity(t *testing.T) *openpgp.Entity {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	entity, err := NewEntity(priv, EntityOptions{
		Name:      "IntentProof Package Repository",
		Email:     "packages@intentproof.io",
		CreatedAt: fixedTime(),
	})
	if err != nil {
		t.Fatalf("new entity: %v", err)
	}
	return entity
}

func fixedTime() time.Time {
	return time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
}

func runGPG(t *testing.T, home string, args ...string) {
	t.Helper()
	base := []string{"--batch", "--no-tty", "--homedir", home}
	cmd := exec.Command("gpg", append(base, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gpg %v: %v\n%s", args, err, out)
	}
}

type badSigner struct{}

func (badSigner) Public() crypto.PublicKey {
	return nil
}

func (badSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}
