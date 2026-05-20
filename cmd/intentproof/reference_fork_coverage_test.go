package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/policy"
)

func TestForkReferencePackCopyDirFailure(t *testing.T) {
	root := writeSampleReferencePack(t)
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", root)
	pack, err := findReferencePack("reference.payments.refund-basic.v1")
	if err != nil {
		t.Fatal(err)
	}
	_ = root
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(blocker, "nested", "fork-dest")
	if err := forkReferencePack(pack, dest, "tnt_copyfail"); err == nil {
		t.Fatal("expected copy/mkdir failure")
	}
}

func TestForkReferencePackStampPolicyMissingFile(t *testing.T) {
	src := filepath.Join(t.TempDir(), "pack-src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "pack.json"), []byte(`{
  "reference_id": "reference.test.missing-policy.v1",
  "domain": "payments", "name": "missing", "version": 1
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	pack := referencePack{
		Dir: src,
		Manifest: referencePackManifest{
			ReferenceID: "reference.test.missing-policy.v1",
		},
	}
	dest := filepath.Join(t.TempDir(), "fork-missing-policy")
	if err := forkReferencePack(pack, dest, "tnt_miss"); err == nil {
		t.Fatal("expected stamp policy read error")
	}
}

func TestRegenerateExpectedRunsInvalidFlowJSON(t *testing.T) {
	packDir := filepath.Join(t.TempDir(), "pack")
	fixtureDir := filepath.Join(packDir, "fixtures", "case1")
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureDir, "flow.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureDir, "attestations.jsonl"), []byte(""), 0o644); err != nil {
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
		t.Fatal("expected flow read/parse error")
	}
}

func TestRegenerateExpectedRunsWriteProtectedFixture(t *testing.T) {
	packDir := filepath.Join(t.TempDir(), "pack")
	fixtureDir := filepath.Join(packDir, "fixtures", "case1")
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureDir, "flow.json"), []byte(`{"flow_id":"f","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureDir, "attestations.jsonl"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixtureDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(fixtureDir, 0o755) })
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
		t.Fatal("expected write expected-run error")
	}
}

func TestReadReferencePackMissingManifestFile(t *testing.T) {
	_, err := readReferencePack(filepath.Join(t.TempDir(), "missing", "pack.json"))
	if err == nil {
		t.Fatal("expected read error")
	}
}

func TestLoadReferencePacksWalkPermissionError(t *testing.T) {
	root := filepath.Join(t.TempDir(), "refs")
	secret := filepath.Join(root, "hidden")
	if err := os.MkdirAll(filepath.Join(secret, "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secret, "deep", "pack.json"), []byte(`{
  "reference_id": "reference.test.walk.v1",
  "domain": "payments", "name": "walk", "version": 1
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secret, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0o755) })
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", root)
	if _, err := loadReferencePacks(); err == nil {
		t.Fatal("expected walk permission error")
	}
}
