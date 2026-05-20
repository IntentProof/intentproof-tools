package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/policy"
)

func TestLoadReferencePacksMissingRoot(t *testing.T) {
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", filepath.Join(t.TempDir(), "missing"))
	if _, err := loadReferencePacks(); err == nil {
		t.Fatal("expected missing root error")
	}
}

func TestFindReferencePackNotFound(t *testing.T) {
	root := writeSampleReferencePack(t)
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", root)
	if _, err := findReferencePack("reference.nope.v1"); err == nil {
		t.Fatal("expected not found error")
	}
}

func TestForkReferencePackStatError(t *testing.T) {
	root := writeSampleReferencePack(t)
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", root)
	pack, err := findReferencePack("reference.payments.refund-basic.v1")
	if err != nil {
		t.Fatal(err)
	}
	// Use a destination path whose parent cannot be created.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(blocker, "child", "dest")
	if err := forkReferencePack(pack, dest, "tnt_x"); err == nil {
		t.Fatal("expected stat/mkdir error")
	}
}

func TestStampPolicyYAMLCompileError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(`
policy_id: reference.payments.refund-basic.v1
tenant_id: reference
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules: []
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := stampPolicyYAML(path, "tnt_x"); err == nil {
		t.Fatal("expected compile error for empty rules")
	}
}

func TestStampFixtureTenantsMissingRoot(t *testing.T) {
	if err := stampFixtureTenants(filepath.Join(t.TempDir(), "missing"), "tnt_x"); err == nil {
		t.Fatal("expected walk error")
	}
}

func TestEnrichForkedFixtureSkipsNilEvent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fixture")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "flow.json"), []byte(`{
  "flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0",
  "events":["not-a-map", {"event_id":"evt_a","action":"placeholder","status":"ok",
    "started_at":"2020-01-01T00:00:00Z","completed_at":"2020-01-01T00:00:01Z"}]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "expected-run.json"), []byte(`{
  "findings":[{"rule_id":"r1","reason":"pass","evidence_event_ids":["evt_a"]}]
}`), 0o644); err != nil {
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
	if err := enrichForkedFixture(dir, compiled); err != nil {
		t.Fatal(err)
	}
}

func TestRegenerateExpectedRunsMissingAttestations(t *testing.T) {
	packDir := filepath.Join(t.TempDir(), "pack")
	fixtureDir := filepath.Join(packDir, "fixtures", "case1")
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureDir, "flow.json"), []byte(`{"flow_id":"f","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`), 0o644); err != nil {
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
		t.Fatal("expected missing attestations error")
	}
}

func TestReferenceForkCommandLoadError(t *testing.T) {
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", filepath.Join(t.TempDir(), "missing"))
	var stdout, stderr bytes.Buffer
	if code := run([]string{
		"reference", "fork", "reference.payments.refund-basic.v1",
		"--to", filepath.Join(t.TempDir(), "dest"),
		"--tenant", "tnt_x",
	}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "reference fork failed") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}
