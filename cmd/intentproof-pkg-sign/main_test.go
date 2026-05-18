package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunRequiresStableCreationTime(t *testing.T) {
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "alias/intentproof/pkg-repo")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "")
	var stdout, stderr bytes.Buffer

	code := run([]string{"export-public-key"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected export-public-key without created-at to fail")
	}
	if !strings.Contains(stderr.String(), "--created-at") {
		t.Fatalf("expected created-at guidance, got %q", stderr.String())
	}
}

func TestRunRequiresKMSKeyID(t *testing.T) {
	t.Setenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID", "")
	t.Setenv("INTENTPROOF_PKG_SIGN_CREATED_AT", "2026-05-17T12:00:00Z")
	var stdout, stderr bytes.Buffer

	code := run([]string{"export-public-key"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected export-public-key without KMS key ID to fail")
	}
	if !strings.Contains(stderr.String(), "--kms-key-id") {
		t.Fatalf("expected KMS key guidance, got %q", stderr.String())
	}
}

func TestShouldPrintExportMessage(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"", false},
		{"-", false},
		{" - ", false},
		{"intentproof.gpg", true},
	}
	for _, tc := range cases {
		if got := shouldPrintExportMessage(tc.path); got != tc.want {
			t.Fatalf("shouldPrintExportMessage(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
