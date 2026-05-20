package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("stdout write failed")
}

func TestRunSignStdoutArmoredDetachSignFailure(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	input := filepath.Join(t.TempDir(), "payload.txt")
	if err := os.WriteFile(input, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := run([]string{"sign", input}, failingWriter{}, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "error:") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunClearSignStdoutArmoredFailure(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	input := filepath.Join(t.TempDir(), "msg.txt")
	if err := os.WriteFile(input, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := run([]string{"clearsign", input}, failingWriter{}, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}

func TestRunExportPublicKeyStdoutArmoredFailure(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	var stderr bytes.Buffer
	if code := run([]string{"export-public-key"}, failingWriter{}, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}
