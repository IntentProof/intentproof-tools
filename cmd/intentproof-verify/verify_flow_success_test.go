package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunFlowVerifyStdoutSuccess(t *testing.T) {
	dir := t.TempDir()
	flow := filepath.Join(dir, "flow.json")
	policy := filepath.Join(dir, "policy.json")
	atts := filepath.Join(dir, "attestations.jsonl")
	if err := os.WriteFile(flow, []byte(`{
  "flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0",
  "events":[{"event_id":"e1","action":"pay","status":"ok",
    "started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"}]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, []byte(`{
  "policy_id":"p1","tenant_id":"tnt","policy_version":1,
  "rules":[{"id":"r1","category":"required","severity":"medium",
    "spec":{"action":"pay","min":1}}]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(atts, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "")
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", "")

	var stdout, stderr bytes.Buffer
	if code := run([]string{flow, policy, atts}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Run Status:") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestRunBundleVerifyStdoutFailMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.proof.tar.zst")
	if err := os.WriteFile(path, []byte("not-a-bundle"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{path}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stdout.String(), "fail") && !strings.Contains(stderr.String(), "error") {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}
