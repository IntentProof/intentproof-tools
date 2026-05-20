package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestForkReferencePackDestinationExists(t *testing.T) {
	root := writeSampleReferencePack(t)
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", root)
	pack, err := findReferencePack("reference.payments.refund-basic.v1")
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "existing")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := forkReferencePack(pack, dest, "tnt_exists"); err == nil {
		t.Fatal("expected destination exists error")
	}
}

func TestForkReferencePackSuccessDirect(t *testing.T) {
	root := writeSampleReferencePack(t)
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", root)
	pack, err := findReferencePack("reference.payments.refund-basic.v1")
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "fork-direct")
	if err := forkReferencePack(pack, dest, "tnt_direct"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "policy.json")); err != nil {
		t.Fatal(err)
	}
}

func TestRunPolicyPublishMissingArgs(t *testing.T) {
	var stderr bytes.Buffer
	if code := runPolicyPublish(nil, nil, &stderr); code == 0 {
		t.Fatal("expected usage failure")
	}
}

func TestRunPolicyActivateMissingArgs(t *testing.T) {
	var stderr bytes.Buffer
	if code := runPolicyActivate(nil, nil, &stderr); code == 0 {
		t.Fatal("expected usage failure")
	}
}
