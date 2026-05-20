package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPolicyPublishInvalidAPIURL(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`policy_id: tnt_x.demo
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
	t.Setenv("INTENTPROOF_QUERY_API_URL", "http://\n")
	t.Setenv("INTENTPROOF_POLICY_SIGNER", "")
	t.Setenv("INTENTPROOF_POLICY_SIGNER_KEY_ID", "")
	t.Setenv("INTENTPROOF_POLICY_SIGNER_PRIVATE_KEY", "")

	var stdout, stderr bytes.Buffer
	if code := runPolicyPublish([]string{policyPath}, &stdout, &stderr); code == 0 {
		t.Fatal("expected publish failure")
	}
	if !strings.Contains(stderr.String(), "publish failed") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunPolicyActivateInvalidAPIURL(t *testing.T) {
	t.Setenv("INTENTPROOF_QUERY_API_URL", "http://\n")
	var stdout, stderr bytes.Buffer
	if code := runPolicyActivate([]string{
		"tnt_x.demo", "1", "--scope", "global", "--effective-at", "2026-01-01T00:00:00Z",
	}, &stdout, &stderr); code == 0 {
		t.Fatal("expected activate failure")
	}
	if !strings.Contains(stderr.String(), "activate failed") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}
