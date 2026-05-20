package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReferenceForkSuccess(t *testing.T) {
	referenceRoot := writeSampleReferencePack(t)
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", referenceRoot)
	dest := filepath.Join(t.TempDir(), "forked-pack")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"reference", "fork", "reference.payments.refund-basic.v1",
		"--to", dest,
		"--tenant", "tnt_fork_ok",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("fork failed: %s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dest, "policy.yaml")); err != nil {
		t.Fatal(err)
	}
	policyYAML, err := os.ReadFile(filepath.Join(dest, "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(policyYAML), "tenant_id: tnt_fork_ok") {
		t.Fatalf("policy=%s", policyYAML)
	}
}
