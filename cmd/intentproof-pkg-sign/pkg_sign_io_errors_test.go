package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRunClearSignMissingInputOpenError(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"clearsign", "/no/such/file"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected open input failure")
	}
}

func TestRunClearSignOutputWriterError(t *testing.T) {
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
	if code := run([]string{"clearsign", "--output", filepath.Join(blocker, "out.asc"), input}, &stdout, &stderr); code == 0 {
		t.Fatal("expected output open failure")
	}
}

func TestRunVerifyAptMetadataVerifyFilesError(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key.asc")
	release := filepath.Join(dir, "Release")
	sig := filepath.Join(dir, "Release.gpg")
	inrelease := filepath.Join(dir, "InRelease")
	for _, p := range []string{key, release, sig, inrelease} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{
		"verify-apt-metadata",
		"--public-key", key,
		"--release", release,
		"--release-sig", sig,
		"--inrelease", inrelease,
	}, &stdout, &stderr); code == 0 {
		t.Fatal("expected verify failure")
	}
}

func TestRunSignUnknownFlagExitsOne(t *testing.T) {
	restore := injectFakeKMSSigner(t)
	defer restore()
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")

	input := filepath.Join(t.TempDir(), "in.txt")
	if err := os.WriteFile(input, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"sign", "--not-a-flag", input}, &stdout, &stderr); code == 0 {
		t.Fatal("expected flag parse failure")
	}
}
