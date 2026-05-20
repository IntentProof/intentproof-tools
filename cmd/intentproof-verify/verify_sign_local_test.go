package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunBundleVerifyFailPrintsMarker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.proof.tar.zst")
	if err := os.WriteFile(path, []byte("not-a-bundle"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{path}, &stdout, &stderr); code == 0 {
		t.Fatal("expected bundle verify failure")
	}
}

func TestRunFlowVerifyMissingPolicyFile(t *testing.T) {
	dir := t.TempDir()
	flow := filepath.Join(dir, "flow.json")
	if err := os.WriteFile(flow, []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{flow, filepath.Join(dir, "missing.json"), filepath.Join(dir, "a.jsonl")}, &stdout, &stderr); code == 0 {
		t.Fatal("expected read error")
	}
	if !strings.Contains(stderr.String(), "error:") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}
