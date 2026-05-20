package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/policy"
)

func TestEnrichForkedFixtureRewritesFlow(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fixture")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "flow.json"), []byte(`{
  "flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0",
  "events":[{"event_id":"evt_a","action":"placeholder","status":"ok",
    "started_at":"2020-01-01T00:00:00Z","completed_at":"2020-01-01T00:00:01Z"}]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "expected-run.json"), []byte(`{
  "findings":[{"rule_id":"req","reason":"pass.required.satisfied","evidence_event_ids":["evt_a"]}]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.Compile([]byte(`
policy_id: tnt_enrich.demo
tenant_id: tnt_enrich
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: pay.run
rules:
  - id: req
    category: required
    severity: high
    spec:
      action: pay.run
      min: 1
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := enrichForkedFixture(dir, compiled); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "flow.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !containsBytes(raw, []byte("pay.run")) {
		t.Fatalf("flow=%s", raw)
	}
}

func containsBytes(b, sub []byte) bool {
	return len(sub) == 0 || (len(b) >= len(sub) && indexBytes(b, sub) >= 0)
}

func indexBytes(b, sub []byte) int {
	for i := 0; i+len(sub) <= len(b); i++ {
		if string(b[i:i+len(sub)]) == string(sub) {
			return i
		}
	}
	return -1
}
