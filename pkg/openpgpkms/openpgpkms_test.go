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

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
)

func TestSelfSignatureIncludesIssuerFingerprint(t *testing.T) {
	entity := testEntity(t)
	identity := entity.PrimaryIdentity()
	if identity == nil || identity.SelfSignature == nil {
		t.Fatal("expected primary identity self-signature")
	}
	got := identity.SelfSignature.IssuerFingerprint
	want := entity.PrimaryKey.Fingerprint[:]
	if len(got) == 0 {
		t.Fatal("expected issuer fingerprint subpacket on self-signature")
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("issuer fingerprint mismatch:\n got %X\nwant %X", got, want)
	}
}

func TestArmoredPublicKeyImportsWithRPMWhenAvailable(t *testing.T) {
	if _, err := exec.LookPath("rpm"); err != nil {
		t.Skip("rpm not installed")
	}
	entity := testEntity(t)
	dir, err := os.MkdirTemp("/tmp", "iprpm-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	keyPath := filepath.Join(dir, "intentproof.gpg")
	rpmDBPath := filepath.Join(dir, "rpmdb")
	if err := os.Mkdir(rpmDBPath, 0o700); err != nil {
		t.Fatalf("create rpm database dir: %v", err)
	}
	var publicKey bytes.Buffer
	if err := ArmoredPublicKey(&publicKey, entity); err != nil {
		t.Fatalf("export public key: %v", err)
	}
	if err := os.WriteFile(keyPath, publicKey.Bytes(), 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	runRPM(t, rpmDBPath, "--import", keyPath)
}

func TestArmoredClearSignVerifiesWithOpenPGP(t *testing.T) {
	entity := testEntity(t)
	message := []byte("Origin: IntentProof\nSuite: stable\n")

	var publicKey bytes.Buffer
	if err := ArmoredPublicKey(&publicKey, entity); err != nil {
		t.Fatalf("export public key: %v", err)
	}
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(publicKey.Bytes()))
	if err != nil {
		t.Fatalf("read armored keyring: %v", err)
	}

	var clearsigned bytes.Buffer
	if err := ArmoredClearSign(&clearsigned, entity, bytes.NewReader(message), fixedTime()); err != nil {
		t.Fatalf("clear sign: %v", err)
	}
	block, _ := clearsign.Decode(clearsigned.Bytes())
	if block == nil {
		t.Fatal("decode clearsigned message")
	}
	if !bytes.Equal(block.Plaintext, message) {
		t.Fatalf("clearsigned plaintext mismatch:\n got %q\nwant %q", block.Plaintext, message)
	}
	if _, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(block.Bytes), block.ArmoredSignature.Body, nil); err != nil {
		t.Fatalf("verify clearsigned message: %v", err)
	}
}

func TestArmoredClearSignVerifiesWithGPGWhenAvailable(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	entity := testEntity(t)
	dir, err := os.MkdirTemp("/tmp", "ipclr-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	messagePath := filepath.Join(dir, "Release")
	inreleasePath := filepath.Join(dir, "InRelease")
	keyPath := filepath.Join(dir, "intentproof.gpg")
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
	var clearsigned bytes.Buffer
	if err := ArmoredClearSign(&clearsigned, entity, bytes.NewReader(message), fixedTime()); err != nil {
		t.Fatalf("clear sign: %v", err)
	}
	if err := os.WriteFile(inreleasePath, clearsigned.Bytes(), 0o644); err != nil {
		t.Fatalf("write InRelease: %v", err)
	}

	home := filepath.Join(dir, "gnupg")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatalf("mkdir gnupg home: %v", err)
	}
	runGPG(t, home, "--import", keyPath)
	runGPG(t, home, "--verify", inreleasePath)
}

func TestArmoredClearSignRequiresCreationTime(t *testing.T) {
	entity := testEntity(t)
	err := ArmoredClearSign(io.Discard, entity, bytes.NewReader([]byte("metadata")), time.Time{})
	if err == nil {
		t.Fatal("expected missing signature creation time to fail")
	}
}

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
	if _, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(message), bytes.NewReader(sig.Bytes()), nil); err != nil {
		t.Fatalf("verify detached signature: %v", err)
	}
}

func TestArmoredDetachSignVerifiesWithGPGWhenAvailable(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	artifacts := writePackageSigningArtifacts(t, "ipgpg-*")
	home := filepath.Join(artifacts.dir, "gnupg")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatalf("mkdir gnupg home: %v", err)
	}

	runGPG(t, home, "--import", artifacts.keyPath)
	runGPG(t, home, "--verify", artifacts.sigPath, artifacts.messagePath)
}

func TestArmoredDetachSignVerifiesWithAptKeyWhenAvailable(t *testing.T) {
	if _, err := exec.LookPath("apt-key"); err != nil {
		t.Skip("apt-key not installed")
	}
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	artifacts := writePackageSigningArtifacts(t, "ipapt-*")
	keyringPath := filepath.Join(artifacts.dir, "intentproof-keyring.gpg")

	cmd := exec.Command("gpg", "--batch", "--yes", "--dearmor", "--output", keyringPath, artifacts.keyPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gpg dearmor: %v\n%s", err, out)
	}
	cmd = exec.Command("apt-key", "--keyring", keyringPath, "verify", artifacts.sigPath, artifacts.messagePath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("apt-key verify: %v\n%s", err, out)
	}
}

func TestRejectsNonRSASigner(t *testing.T) {
	_, err := NewEntity(badSigner{}, EntityOptions{CreatedAt: fixedTime()})
	if err == nil {
		t.Fatal("expected non-RSA signer to fail")
	}
}

func TestNewEntityRequiresCreationTime(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	_, err = NewEntity(priv, EntityOptions{})
	if err == nil {
		t.Fatal("expected missing creation time to fail")
	}
}

func TestArmoredDetachSignRequiresCreationTime(t *testing.T) {
	entity := testEntity(t)
	err := ArmoredDetachSign(io.Discard, entity, bytes.NewReader([]byte("metadata")), time.Time{})
	if err == nil {
		t.Fatal("expected missing signature creation time to fail")
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

type packageSigningArtifacts struct {
	dir         string
	keyPath     string
	messagePath string
	sigPath     string
}

func writePackageSigningArtifacts(t *testing.T, pattern string) packageSigningArtifacts {
	t.Helper()
	entity := testEntity(t)
	dir, err := os.MkdirTemp("/tmp", pattern)
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	artifacts := packageSigningArtifacts{
		dir:         dir,
		keyPath:     filepath.Join(dir, "intentproof.gpg"),
		messagePath: filepath.Join(dir, "Release"),
		sigPath:     filepath.Join(dir, "Release.gpg"),
	}
	message := []byte("Origin: IntentProof\nSuite: stable\n")
	if err := os.WriteFile(artifacts.messagePath, message, 0o644); err != nil {
		t.Fatalf("write message: %v", err)
	}
	var publicKey bytes.Buffer
	if err := ArmoredPublicKey(&publicKey, entity); err != nil {
		t.Fatalf("export public key: %v", err)
	}
	if err := os.WriteFile(artifacts.keyPath, publicKey.Bytes(), 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	var sig bytes.Buffer
	if err := ArmoredDetachSign(&sig, entity, bytes.NewReader(message), fixedTime()); err != nil {
		t.Fatalf("detach sign: %v", err)
	}
	if err := os.WriteFile(artifacts.sigPath, sig.Bytes(), 0o644); err != nil {
		t.Fatalf("write signature: %v", err)
	}
	return artifacts
}

func runGPG(t *testing.T, home string, args ...string) {
	t.Helper()
	base := []string{"--batch", "--no-tty", "--homedir", home}
	cmd := exec.Command("gpg", append(base, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gpg %v: %v\n%s", args, err, out)
	}
}

func runRPM(t *testing.T, dbpath string, args ...string) {
	t.Helper()
	base := []string{"--dbpath", dbpath}
	cmd := exec.Command("rpm", append(base, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("rpm %v: %v\n%s", args, err, out)
	}
}

type badSigner struct{}

func (badSigner) Public() crypto.PublicKey {
	return nil
}

func (badSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}
