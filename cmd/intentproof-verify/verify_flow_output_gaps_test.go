package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunFlowVerifyWriteOutputPermissionDenied(t *testing.T) {
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
	t.Setenv("INTENTPROOF_POLICY_SIGNER", "")
	t.Setenv("INTENTPROOF_POLICY_SIGNER_KEY_ID", "")
	t.Setenv("INTENTPROOF_POLICY_SIGNER_PRIVATE_KEY", "")

	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(blocker, "out.json")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--output", out, flow, policy, att}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "write output") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestRunFlowVerifyInvalidFlowJSON(t *testing.T) {
	dir := t.TempDir()
	flow := filepath.Join(dir, "flow.json")
	policy := filepath.Join(dir, "policy.json")
	att := filepath.Join(dir, "att.jsonl")
	if err := os.WriteFile(flow, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(att, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{flow, policy, att}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "error:") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestRunFlowVerifyKMSInitFailure(t *testing.T) {
	dir := t.TempDir()
	flow := filepath.Join(dir, "flow.json")
	policy := filepath.Join(dir, "policy.json")
	att := filepath.Join(dir, "att.jsonl")
	if err := os.WriteFile(flow, []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(att, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "alias/test")
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", "")

	var stdout, stderr bytes.Buffer
	if code := run([]string{flow, policy, att}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "error:") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}
