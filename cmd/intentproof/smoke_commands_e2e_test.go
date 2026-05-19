package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSmokePolicyLintAndInitTemplate(t *testing.T) {
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`
policy_id: tnt_acme.demo
tenant_id: tnt_acme
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

	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "lint", policyPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("lint: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "fingerprint:") {
		t.Fatalf("stdout=%s", stdout.String())
	}

	root := t.TempDir()
	writeNodeProject(t, root)
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"init", "--template", "stripe-refund"}, &stdout, &stderr); code != 0 {
		t.Fatalf("init template: %s", stderr.String())
	}
}

func writeNodeProject(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"dependencies":{"stripe":"^15.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	prev, _ := os.Getwd()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
}
