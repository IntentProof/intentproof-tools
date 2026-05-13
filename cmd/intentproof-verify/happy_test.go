package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHappyPathVerify(t *testing.T) {
	dir := t.TempDir()
	flowPath := filepath.Join(dir, "flow.json")
	policyPath := filepath.Join(dir, "policy.json")
	attPath := filepath.Join(dir, "attestations.jsonl")

	if err := os.WriteFile(flowPath, []byte(`{"events":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	policy := `{"rules":[]}`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(attPath, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{flowPath, policyPath, attPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d: stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Run Status:") {
		t.Fatalf("expected Run Status in output, got: %s", stdout.String())
	}
	if strings.TrimSpace(stderr.String()) != "" {
		t.Fatalf("expected empty stderr, got: %s", stderr.String())
	}
}
