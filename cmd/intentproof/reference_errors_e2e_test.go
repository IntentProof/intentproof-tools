package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReferenceForkRequiresFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"reference", "fork", "reference.payments.refund-basic.v1"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure without --to and --tenant")
	}
	if !strings.Contains(stderr.String(), "--to is required") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestReferenceForkRejectsExistingDestination(t *testing.T) {
	referenceRoot := writeSampleReferencePack(t)
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", referenceRoot)
	dest := filepath.Join(t.TempDir(), "dest")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"reference", "fork", "reference.payments.refund-basic.v1",
		"--to", dest, "--tenant", "tnt_acme",
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected failure when destination exists")
	}
	if !strings.Contains(stderr.String(), "already exists") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestReferenceListRejectsExtraArgs(t *testing.T) {
	referenceRoot := writeSampleReferencePack(t)
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", referenceRoot)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"reference", "list", "extra"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}
