package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReferenceForkUnknownReference(t *testing.T) {
	referenceRoot := writeSampleReferencePack(t)
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", referenceRoot)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"reference", "fork", "reference.payments.missing.v1",
		"--to", filepath.Join(t.TempDir(), "dest"),
		"--tenant", "tnt_x",
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "not found") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestReferenceForkUnknownFlag(t *testing.T) {
	referenceRoot := writeSampleReferencePack(t)
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", referenceRoot)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"reference", "fork", "reference.payments.refund-basic.v1",
		"--to", filepath.Join(t.TempDir(), "dest"),
		"--tenant", "tnt_x",
		"--extra",
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected failure")
	}
}

func TestReferenceListInvalidPackJSON(t *testing.T) {
	root := filepath.Join(t.TempDir(), "reference-policies")
	packDir := filepath.Join(root, "bad", "v1")
	if err := os.MkdirAll(packDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "pack.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", root)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"reference", "list"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected parse failure")
	}
}

func TestTenantPolicyIDNonReferencePrefix(t *testing.T) {
	got := tenantPolicyID("custom.policy", "tnt_acme")
	if got != "tnt_acme.custom.policy" {
		t.Fatalf("got %s", got)
	}
}
