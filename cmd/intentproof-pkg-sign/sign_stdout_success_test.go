package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRunSignStdoutSuccess(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	dir := t.TempDir()
	input := filepath.Join(dir, "payload.txt")
	if err := os.WriteFile(input, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"sign", input}, &stdout, &stderr); code != 0 {
		t.Fatalf("sign failed: %s", stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatal("expected armored signature on stdout")
	}
}

func TestRunClearSignStdoutSuccess(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	dir := t.TempDir()
	input := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(input, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"clearsign", input}, &stdout, &stderr); code != 0 {
		t.Fatalf("clearsign failed: %s", stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatal("expected clearsigned output on stdout")
	}
}
