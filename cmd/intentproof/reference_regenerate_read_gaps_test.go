package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/policy"
)

func TestRegenerateExpectedRunsMissingFlowJSON(t *testing.T) {
	root := writeSampleReferencePack(t)
	dest := filepath.Join(t.TempDir(), "fork-regen")
	if err := forkReferencePack(mustFindSamplePack(t, root), dest, "tnt_regen"); err != nil {
		t.Fatal(err)
	}
	fixtureDir := filepath.Join(dest, "fixtures", "happy-path")
	if err := os.Remove(filepath.Join(fixtureDir, "flow.json")); err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.CompileFile(filepath.Join(dest, "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := regenerateExpectedRuns(dest, compiled); err == nil {
		t.Fatal("expected missing flow.json error")
	}
}

func TestRegenerateExpectedRunsMissingAttestationsAfterFork(t *testing.T) {
	root := writeSampleReferencePack(t)
	dest := filepath.Join(t.TempDir(), "fork-att")
	if err := forkReferencePack(mustFindSamplePack(t, root), dest, "tnt_att"); err != nil {
		t.Fatal(err)
	}
	fixtureDir := filepath.Join(dest, "fixtures", "happy-path")
	if err := os.Remove(filepath.Join(fixtureDir, "attestations.jsonl")); err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.CompileFile(filepath.Join(dest, "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := regenerateExpectedRuns(dest, compiled); err == nil {
		t.Fatal("expected missing attestations error")
	}
}

func mustFindSamplePack(t *testing.T, root string) referencePack {
	t.Helper()
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", root)
	pack, err := findReferencePack("reference.payments.refund-basic.v1")
	if err != nil {
		t.Fatal(err)
	}
	return pack
}

func TestEnrichForkedFixturesPropagatesFixtureError(t *testing.T) {
	root := filepath.Join(t.TempDir(), "fixtures-root")
	fixtureDir := filepath.Join(root, "broken")
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureDir, "expected-run.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.Compile(wrapReferencePolicyYAML())
	if err != nil {
		t.Fatal(err)
	}
	err = enrichForkedFixtures(root, compiled)
	if err == nil || !strings.Contains(err.Error(), "expected-run.json") {
		t.Fatalf("err=%v", err)
	}
}

func wrapReferencePolicyYAML() []byte {
	return []byte(`policy_id: reference.demo
tenant_id: reference
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: required-refund-created
    category: required
    severity: high
    spec:
      action: payments.refund.create
      min: 1
`)
}
