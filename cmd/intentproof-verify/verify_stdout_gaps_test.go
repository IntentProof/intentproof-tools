package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPrintsVersionFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "intentproof-verify") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestRunFlowVerifyPrintsStatusStdout(t *testing.T) {
	dir := t.TempDir()
	flow := filepath.Join(dir, "flow.json")
	policy := filepath.Join(dir, "policy.json")
	att := filepath.Join(dir, "att.jsonl")
	if err := os.WriteFile(flow, []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000000000000000000000000000000000000000000000000000000000000000","events":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"spec_version":"1.0.0","rules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(att, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "")
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", "")
	var stdout, stderr bytes.Buffer
	if code := run([]string{flow, policy, att}, &stdout, &stderr); code != 0 {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Run Status:") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestRunFlowVerifyUsageWhenArgsMissing(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"only.json"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected usage failure")
	}
}
