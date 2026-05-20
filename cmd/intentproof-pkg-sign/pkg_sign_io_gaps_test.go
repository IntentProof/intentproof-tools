package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunSignOpenInputFailureWithFakeKMS(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"sign", filepath.Join(t.TempDir(), "missing.txt")}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "open input") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunClearSignOpenInputFailureWithFakeKMS(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"clearsign", filepath.Join(t.TempDir(), "missing.txt")}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "open input") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunExportPublicKeyArmoredFailure(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	outPath := filepath.Join(t.TempDir(), "key.asc")
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if err := os.Chmod(outPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(outPath, 0o644) })

	var stdout, stderr bytes.Buffer
	if code := run([]string{"export-public-key", "--output", outPath}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}