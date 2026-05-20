package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/verifier"
)

func TestRunOneFixtureMatchesWithIgnoredTimestamps(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fixture")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"pay","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"required","severity":"medium","spec":{"action":"pay","min":1}
}]}`)
	if err := os.WriteFile(filepath.Join(dir, "flow.json"), flow, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "attestations.jsonl"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	run, err := verifier.Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	run.StartedAt = "2020-01-01T00:00:00Z"
	run.CompletedAt = "2020-01-02T00:00:00Z"
	raw, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "expected-run.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	ok, generated, err := runOneFixture(dir, policy)
	if err != nil || !ok || generated {
		t.Fatalf("ok=%v generated=%v err=%v", ok, generated, err)
	}
}

func TestRunOneFixtureGeneratesMissingExpected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fixture")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "flow.json"), []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "attestations.jsonl"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]}`)
	ok, generated, err := runOneFixture(dir, policy)
	if err != nil || !ok || !generated {
		t.Fatalf("ok=%v generated=%v err=%v", ok, generated, err)
	}
}
