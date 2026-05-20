package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/policy"
)

func TestUpdateJSONFileWriteError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "doc.json")
	if err := os.WriteFile(path, []byte(`{"a":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := updateJSONFile(filepath.Join(blocker, "doc.json"), func(map[string]any) {})
	if err == nil {
		t.Fatal("expected write error")
	}
}

func TestStampPolicyYAMLWriteError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(`
policy_id: reference.payments.refund-basic.v1
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
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
	if _, _, err := stampPolicyYAML(path, "tnt_w"); err == nil {
		t.Fatal("expected write error")
	}
}

func TestEnrichForkedFixturesListError(t *testing.T) {
	if err := enrichForkedFixtures(filepath.Join(t.TempDir(), "missing"), nil); err == nil {
		t.Fatal("expected list fixture dirs error")
	}
}

func TestAssignEvidenceActionsCardinalityBranch(t *testing.T) {
	out := map[string]string{}
	assignEvidenceActions(policy.CanonicalRule{
		Category: "cardinality",
		Spec:     map[string]any{"action": "card.action"},
	}, []string{"e1", "e2"}, out)
	if out["e1"] != "card.action" || out["e2"] != "card.action" {
		t.Fatalf("out=%v", out)
	}
}
