package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestForkReferencePackUsesDefaultPolicyPaths(t *testing.T) {
	root := t.TempDir()
	packDir := filepath.Join(root, "payments", "minimal", "v1")
	fixtureDir := filepath.Join(packDir, "fixtures", "case1")
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		filepath.Join(packDir, "pack.json"): `{
  "reference_id": "reference.payments.minimal.v1",
  "domain": "payments",
  "name": "minimal",
  "version": 1,
  "display_name": "Minimal",
  "summary": "Defaults policy paths."
}`,
		filepath.Join(packDir, "policy.yaml"): `policy_id: reference.payments.minimal.v1
tenant_id: reference
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 1
policy_fingerprint: sha256:placeholder
`,
		filepath.Join(fixtureDir, "flow.json"): `{"flow_id":"f1","tenant_id":"reference","flow_merkle_root":"sha256:0","events":[
  {"event_id":"evt_a","action":"demo.action","status":"ok","started_at":"2020-01-01T00:00:00Z","completed_at":"2020-01-01T00:00:01Z"}
]}`,
		filepath.Join(fixtureDir, "attestations.jsonl"): "",
		filepath.Join(fixtureDir, "expected-run.json"): `{
  "findings":[{"rule_id":"r1","reason":"pass.required.satisfied","evidence_event_ids":["evt_a"]}]
}
`,
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", root)
	pack, err := findReferencePack("reference.payments.minimal.v1")
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "fork-minimal")
	if err := forkReferencePack(pack, dest, "tnt_min"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "policy.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "policy.json")); err != nil {
		t.Fatal(err)
	}
}