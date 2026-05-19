package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/intentproof/intentproof-tools/pkg/openpgpkms"
)

type pkgSignFakeKMS struct {
	priv      *rsa.PrivateKey
	publicDER []byte
}

func (c *pkgSignFakeKMS) GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return &kms.GetPublicKeyOutput{
		KeySpec:           types.KeySpecRsa4096,
		KeyUsage:          types.KeyUsageTypeSignVerify,
		PublicKey:         c.publicDER,
		SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecRsassaPkcs1V15Sha512},
	}, nil
}

func (c *pkgSignFakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.priv, crypto.SHA512, in.Message)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{Signature: sig}, nil
}

func TestPkgSignAptMetadataRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	restore := newPkgSignKMSSigner
	newPkgSignKMSSigner = func(ctx context.Context, keyID string) (*openpgpkms.KMSSigner, error) {
		return openpgpkms.NewKMSSignerFromClient(ctx, &pkgSignFakeKMS{priv: priv, publicDER: publicDER}, keyID)
	}
	t.Cleanup(func() { newPkgSignKMSSigner = restore })

	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/intentproof/pkg-repo")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	dir := t.TempDir()
	releasePath := filepath.Join(dir, "Release")
	message := []byte("Origin: IntentProof\nSuite: stable\n")
	if err := os.WriteFile(releasePath, message, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{
		"export-public-key",
		"--output", filepath.Join(dir, "intentproof.gpg"),
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("export-public-key: code=%d stderr=%s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"sign",
		"--output", filepath.Join(dir, "Release.gpg"),
		releasePath,
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("sign: code=%d stderr=%s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"clearsign",
		"--output", filepath.Join(dir, "InRelease"),
		releasePath,
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("clearsign: code=%d stderr=%s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"verify-apt-metadata",
		"--public-key", filepath.Join(dir, "intentproof.gpg"),
		"--release", releasePath,
		"--release-sig", filepath.Join(dir, "Release.gpg"),
		"--inrelease", filepath.Join(dir, "InRelease"),
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("verify-apt-metadata: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "PASS") {
		t.Fatalf("expected PASS output, got %q", stdout.String())
	}
}

func TestPkgSignUsageAndValidation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure with no args")
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("stderr=%q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"unknown-cmd"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected unknown command failure")
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"sign", "--created-at", "2026-05-17T12:00:00Z", t.TempDir()}, &stdout, &stderr); code == 0 {
		t.Fatal("expected sign without kms key to fail")
	}
}

func TestPkgSignExportPublicKeyPrintsFingerprint(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	restore := newPkgSignKMSSigner
	newPkgSignKMSSigner = func(ctx context.Context, keyID string) (*openpgpkms.KMSSigner, error) {
		return openpgpkms.NewKMSSignerFromClient(ctx, &pkgSignFakeKMS{priv: priv, publicDER: publicDER}, keyID)
	}
	t.Cleanup(func() { newPkgSignKMSSigner = restore })

	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	outPath := filepath.Join(t.TempDir(), "intentproof.gpg")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"export-public-key", "--output", outPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("export: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "exported OpenPGP public key") {
		t.Fatalf("stdout=%q", stdout.String())
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatal(err)
	}
}

func TestPkgSignEntityFromOptionsRejectsBadCreatedAt(t *testing.T) {
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "not-a-time")
	if _, _, err := entityFromOptions(commandOptions{}); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestPkgSignSignRequiresExactlyOneInput(t *testing.T) {
	restore := newPkgSignKMSSigner
	newPkgSignKMSSigner = func(ctx context.Context, keyID string) (*openpgpkms.KMSSigner, error) {
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		publicDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		return openpgpkms.NewKMSSignerFromClient(ctx, &pkgSignFakeKMS{priv: priv, publicDER: publicDER}, keyID)
	}
	t.Cleanup(func() { newPkgSignKMSSigner = restore })
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"sign", "--created-at", "2026-05-17T12:00:00Z", "--kms-key-id", "alias/test"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected missing input file to fail")
	}
}

// Ensure digest signing path is exercised through the fake KMS stack.
func TestPkgSignFakeKMSSignsSHA512Digest(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	client := &pkgSignFakeKMS{priv: priv, publicDER: publicDER}
	signer, err := openpgpkms.NewKMSSignerFromClient(context.Background(), client, "alias/test")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum512([]byte("metadata"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA512); err != nil {
		t.Fatal(err)
	}
}
