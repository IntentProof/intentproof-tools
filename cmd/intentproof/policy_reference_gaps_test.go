package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunOneFixtureReadAttestationsError(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fixture")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "flow.json"), []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := runOneFixture(dir, []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]}`))
	if err == nil {
		t.Fatal("expected read attestations error")
	}
}

func TestRunOneFixtureWriteExpectedRunError(t *testing.T) {
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
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	_, _, err := runOneFixture(dir, []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]}`))
	if err == nil {
		t.Fatal("expected write expected-run error")
	}
}

func TestFindSinglePolicyYAMLReadDirError(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := findSinglePolicyYAML(blocker); err == nil {
		t.Fatal("expected readdir error")
	}
}

func TestForkReferencePackCopyDirRelError(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "ok.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), string([]byte{0}))
	if err := copyDir(src, dest); err == nil {
		t.Skip("platform accepted null-byte dest")
	}
}
