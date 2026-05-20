package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunSignWritesDetachedSignatureToStdout(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	input := filepath.Join(t.TempDir(), "payload.txt")
	if err := os.WriteFile(input, []byte("release metadata"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"sign", input}, &stdout, &stderr); code != 0 {
		t.Fatalf("sign failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "BEGIN PGP SIGNATURE") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestRunClearSignMissingInputFile(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"clearsign", filepath.Join(t.TempDir(), "missing.txt")}, &stdout, &stderr); code == 0 {
		t.Fatal("expected open error")
	}
	if !strings.Contains(stderr.String(), "open input") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestRunExportPublicKeyToStdout(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"export-public-key"}, &stdout, &stderr); code != 0 {
		t.Fatalf("export failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}
