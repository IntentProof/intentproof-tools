package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/openpgpkms"
)

func injectFakeKMSSigner(t *testing.T) func() {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	prev := newPkgSignKMSSigner
	newPkgSignKMSSigner = func(ctx context.Context, keyID string) (*openpgpkms.KMSSigner, error) {
		return openpgpkms.NewKMSSignerFromClient(ctx, &pkgSignFakeKMS{priv: priv, publicDER: publicDER}, keyID)
	}
	return func() { newPkgSignKMSSigner = prev }
}

func TestRunSignOutputFileError(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "in.txt")
	if err := os.WriteFile(input, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"sign", "--output", filepath.Join(blocker, "out.asc"), input}, &stdout, &stderr); code == 0 {
		t.Fatal("expected output open failure")
	}
}

func TestRunExportPublicKeyRejectsPositionalArgs(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"export-public-key", "extra"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}

func TestRunClearSignOutputToStdout(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	input := filepath.Join(t.TempDir(), "release.txt")
	if err := os.WriteFile(input, []byte("Origin: test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"clearsign", "--output", "-", input}, &stdout, &stderr); code != 0 {
		t.Fatalf("clearsign: %s", stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatal("expected stdout output")
	}
}
