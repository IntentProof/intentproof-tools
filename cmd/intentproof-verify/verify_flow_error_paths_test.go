package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunFlowVerifyAttestationsFileMissing(t *testing.T) {
	dir := t.TempDir()
	flow := filepath.Join(dir, "flow.json")
	policy := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(flow, []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{flow, policy, filepath.Join(dir, "missing.jsonl")}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "missing.jsonl") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestRunFlowVerifyPolicyFileMissing(t *testing.T) {
	dir := t.TempDir()
	flow := filepath.Join(dir, "flow.json")
	if err := os.WriteFile(flow, []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{flow, filepath.Join(dir, "missing.json"), filepath.Join(dir, "a.jsonl")}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "missing.json") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestRunBundleVerifyWriteOutputPermissionDenied(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.proof.tar.zst")
	if err := os.WriteFile(path, []byte("not-a-bundle"), 0o644); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--output", filepath.Join(blocker, "out.json"), path}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}

func TestRunBundleVerifyMissingInputPath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"/no/such/bundle.proof.tar.zst"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "bundle.proof.tar.zst") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}
