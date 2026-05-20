package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRunSignWritesDetachedSignatureToFile(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	dir := t.TempDir()
	input := filepath.Join(dir, "payload.txt")
	output := filepath.Join(dir, "payload.asc")
	if err := os.WriteFile(input, []byte("payload bytes"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"sign", "--output", output, input}, &stdout, &stderr); code != 0 {
		t.Fatalf("sign failed: %s", stderr.String())
	}
	raw, err := os.ReadFile(output)
	if err != nil || len(raw) == 0 {
		t.Fatalf("output err=%v len=%d", err, len(raw))
	}
}

func TestRunClearSignWritesToFile(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	dir := t.TempDir()
	input := filepath.Join(dir, "release.txt")
	output := filepath.Join(dir, "release.asc")
	if err := os.WriteFile(input, []byte("Origin: test\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"clearsign", "--output", output, input}, &stdout, &stderr); code != 0 {
		t.Fatalf("clearsign failed: %s", stderr.String())
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatal(err)
	}
}

func TestRunExportPublicKeyWritesFileAndMessage(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	output := filepath.Join(t.TempDir(), "repo.pub.asc")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"export-public-key", "--output", output}, &stdout, &stderr); code != 0 {
		t.Fatalf("export failed: %s", stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatal("expected export confirmation on stdout")
	}
}

func TestRunSignMissingInputArg(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"sign"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected missing input failure")
	}
}
