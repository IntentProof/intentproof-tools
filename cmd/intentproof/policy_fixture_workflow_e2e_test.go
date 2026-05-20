package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyTestGeneratesExpectedRun(t *testing.T) {
	root := t.TempDir()
	policyPath := filepath.Join(root, "policy.yaml")
	fixDir := filepath.Join(root, "fixtures", "gen")
	if err := os.MkdirAll(fixDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte(`
policy_id: tnt_gen.demo
tenant_id: tnt_gen
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
	if err := os.WriteFile(filepath.Join(fixDir, "flow.json"), []byte(`{
  "flow_id":"f1","tenant_id":"tnt_gen","flow_merkle_root":"sha256:00",
  "events":[{"event_id":"e1","action":"demo.action","status":"ok",
    "started_at":"2026-05-16T00:00:00Z","completed_at":"2026-05-16T00:00:01Z"}]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixDir, "attestations.jsonl"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "test", root}, &stdout, &stderr); code != 0 {
		t.Fatalf("test failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "generated") {
		t.Fatalf("stdout=%s", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(fixDir, "expected-run.json")); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyTestReportsMismatch(t *testing.T) {
	root := t.TempDir()
	policyPath := filepath.Join(root, "policy.yaml")
	fixDir := filepath.Join(root, "fixtures", "bad")
	if err := os.MkdirAll(fixDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte(`
policy_id: tnt_bad.demo
tenant_id: tnt_bad
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
	if err := os.WriteFile(filepath.Join(fixDir, "flow.json"), []byte(`{
  "flow_id":"f1","tenant_id":"tnt_bad","flow_merkle_root":"sha256:00","events":[]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixDir, "attestations.jsonl"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixDir, "expected-run.json"), []byte(`{"status":"pass"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "test", root}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stdout.String(), "run mismatch") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestPolicyTestRejectsMultipleYAML(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.yaml"), []byte("x: 1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.yml"), []byte("y: 2"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "test", root}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}
