package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/policy"
)

func TestRegenerateExpectedRunsVerifyFailure(t *testing.T) {
	packDir := filepath.Join(t.TempDir(), "pack")
	fixtureDir := filepath.Join(packDir, "fixtures", "case1")
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureDir, "flow.json"), []byte(`{
  "flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureDir, "attestations.jsonl"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.Compile([]byte(`
policy_id: tnt_x.demo
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
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := regenerateExpectedRuns(packDir, compiled); err == nil {
		t.Fatal("expected verify failure")
	}
}

func TestWriteCanonicalPolicyJSONReadOnlyDir(t *testing.T) {
	compiled, err := policy.Compile([]byte(`
policy_id: tnt_wc.demo
tenant_id: tnt_wc
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
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	err = writeCanonicalPolicyJSON(filepath.Join(dir, "policy.json"), compiled)
	if err == nil {
		t.Fatal("expected write error")
	}
}

func TestUpdateJSONFileParseError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := updateJSONFile(path, func(map[string]any) {}); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestAssignEvidenceActionsEmptyEventIDsNoOp(t *testing.T) {
	out := map[string]string{"keep": "x"}
	assignEvidenceActions(policy.CanonicalRule{Category: "required", Spec: map[string]any{"action": "pay"}}, nil, out)
	if len(out) != 1 {
		t.Fatalf("out=%v", out)
	}
}

func TestCopyDirWalkReadError(t *testing.T) {
	root := filepath.Join(t.TempDir(), "src")
	secret := filepath.Join(root, "hidden")
	if err := os.MkdirAll(filepath.Join(secret, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secret, "nested", "file.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secret, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0o755) })
	if err := copyDir(root, filepath.Join(t.TempDir(), "dest")); err == nil {
		t.Fatal("expected copy walk error")
	}
}
