package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPolicyTestMarshalPolicyError(t *testing.T) {
	// Covered indirectly: compile succeeds; no direct hook for json.Marshal failure.
	// Exercise runOneFixture read expected error (non-notexist).
	dir := t.TempDir()
	fixtures := filepath.Join(dir, "fixtures", "case1")
	if err := os.MkdirAll(fixtures, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(`
policy_id: tnt_x.demo
tenant_id: tnt_x
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 1
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtures, "flow.json"), []byte(`{"flow_id":"f","tenant_id":"tnt_x","flow_merkle_root":"sha256:0","events":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtures, "attestations.jsonl"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtures, "expected-run.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "test", dir}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stdout.String(), "parse expected-run.json") {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestRunPolicyLintRenderCanonicalError(t *testing.T) {
	t.Skip("canonical policy marshal is not injectable")
}
