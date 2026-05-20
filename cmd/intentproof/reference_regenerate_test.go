package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/policy"
)

func TestRegenerateExpectedRuns(t *testing.T) {
	root := t.TempDir()
	fixDir := filepath.Join(root, "fixtures", "case1")
	if err := os.MkdirAll(fixDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixDir, "flow.json"), []byte(`{
  "flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0",
  "events":[{"event_id":"e1","action":"demo.action","status":"ok",
    "started_at":"2026-05-16T00:00:00Z","completed_at":"2026-05-16T00:00:01Z"}]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixDir, "attestations.jsonl"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`
policy_id: tnt_regen.demo
tenant_id: tnt
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 1
`)
	compiled, err := policy.Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := regenerateExpectedRuns(root, compiled); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(fixDir, "expected-run.json")); err != nil {
		t.Fatal(err)
	}
}
