package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunOneFixtureDetectsMismatchWithoutTimestamps(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(dir, "expected-run.json"), []byte(`{"status":"fail","findings":[]}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]}`)
	ok, generated, err := runOneFixture(dir, policy)
	if err != nil {
		t.Fatal(err)
	}
	if ok || generated {
		t.Fatalf("ok=%v generated=%v", ok, generated)
	}
}

func TestJsonEqualIgnoreTimestampsRequiresTimestampKeys(t *testing.T) {
	expected := map[string]interface{}{"status": "pass"}
	actual := map[string]interface{}{"status": "pass", "started_at": "2026-01-01T00:00:00Z"}
	if jsonEqualIgnoreTimestamps(expected, actual) {
		t.Fatal("expected false when expected lacks started_at")
	}
}
