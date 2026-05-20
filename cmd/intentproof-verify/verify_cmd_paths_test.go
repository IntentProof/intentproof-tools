package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunBundleVerifyFailStdout(t *testing.T) {
	// Invalid bundle bytes should fail verify.
	var stdout, stderr strings.Builder
	code := run([]string{"/dev/null"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected failure for invalid bundle")
	}
}

func TestRunFlowVerifyWithOutput(t *testing.T) {
	dir := t.TempDir()
	flow := filepath.Join(dir, "flow.json")
	policy := filepath.Join(dir, "policy.json")
	atts := filepath.Join(dir, "atts.jsonl")
	if err := os.WriteFile(flow, []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(atts, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "run.json")
	var stdout, stderr bytes.Buffer
	code := run([]string{"--output", out, flow, policy, atts}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify: %s", stderr.String())
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal(err)
	}
}

func TestRunFlowVerifyPrintsStatus(t *testing.T) {
	dir := t.TempDir()
	flow := filepath.Join(dir, "flow.json")
	policy := filepath.Join(dir, "policy.json")
	atts := filepath.Join(dir, "atts.jsonl")
	if err := os.WriteFile(flow, []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(atts, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{flow, policy, atts}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Run Status:") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestRunMissingInputFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"/no/such/flow.json", "p", "a"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected error")
	}
}
