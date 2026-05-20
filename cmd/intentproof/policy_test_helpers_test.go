package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/policy"
)

func policyCompileMinimal(t *testing.T) (*policy.CompileResult, error) {
	t.Helper()
	return policy.Compile([]byte(`
policy_id: tnt_min.demo
tenant_id: tnt_min
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 1
`))
}

func TestJSONEqualIgnoreTimestampsNonMap(t *testing.T) {
	if !jsonEqualIgnoreTimestamps(1, 1) {
		t.Fatal("expected equal scalars")
	}
	if jsonEqualIgnoreTimestamps(1, 2) {
		t.Fatal("expected unequal scalars")
	}
}

func TestJSONEqualIgnoreTimestampsMissingTimestamp(t *testing.T) {
	left := map[string]interface{}{"started_at": "2026-01-01T00:00:00Z"}
	right := map[string]interface{}{"status": "pass"}
	if jsonEqualIgnoreTimestamps(left, right) {
		t.Fatal("expected false when timestamp keys differ")
	}
}

func TestJSONEqualIgnoreTimestampsIgnoresClockFields(t *testing.T) {
	left := map[string]interface{}{
		"status":       "pass",
		"started_at":   "2026-01-01T00:00:00Z",
		"completed_at": "2026-01-02T00:00:00Z",
	}
	right := map[string]interface{}{
		"status":       "pass",
		"started_at":   "2099-01-01T00:00:00Z",
		"completed_at": "2099-01-02T00:00:00Z",
	}
	if !jsonEqualIgnoreTimestamps(left, right) {
		t.Fatal("expected equal when only timestamps differ")
	}
}

func TestFindSinglePolicyYAMLErrors(t *testing.T) {
	root := t.TempDir()
	if _, err := findSinglePolicyYAML(root); err == nil {
		t.Fatal("expected no yaml error")
	}
	if err := os.WriteFile(filepath.Join(root, "a.yaml"), []byte("x: 1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.yml"), []byte("y: 2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := findSinglePolicyYAML(root); err == nil {
		t.Fatal("expected multiple yaml error")
	}
}

func TestListFixtureDirsRejectsEmpty(t *testing.T) {
	root := filepath.Join(t.TempDir(), "fixtures")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := listFixtureDirs(root); err == nil {
		t.Fatal("expected no fixtures error")
	}
}

func TestRunOneFixtureGenerateWhenMissing(t *testing.T) {
	dir := t.TempDir()
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	policyJSON := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]}`)
	if err := os.WriteFile(filepath.Join(dir, "flow.json"), flow, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "attestations.jsonl"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	ok, generated, err := runOneFixture(dir, policyJSON)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || !generated {
		t.Fatalf("ok=%v generated=%v", ok, generated)
	}
}
