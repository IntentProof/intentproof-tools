package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"nope"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "Unknown command") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunSignMissingInputFile(t *testing.T) {
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"sign", "/no/such/file"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}

func TestRunClearSignRequiresOneArg(t *testing.T) {
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"clearsign"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}

func TestRunVerifyAptMetadataMissingFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify-apt-metadata"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}

func TestOutputWriterCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.asc")
	var stdout bytes.Buffer
	w, closeFn, err := outputWriter(path, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	if closeFn == nil {
		t.Fatal("expected closer")
	}
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	closeFn()
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
