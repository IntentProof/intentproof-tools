package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyDiffReportsChanges(t *testing.T) {
	dir := t.TempDir()
	left := filepath.Join(dir, "left.yaml")
	right := filepath.Join(dir, "right.yaml")
	if err := os.WriteFile(left, []byte(`
policy_id: tnt_diff.left
tenant_id: tnt_diff
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
	if err := os.WriteFile(right, []byte(`
policy_id: tnt_diff.right
tenant_id: tnt_diff
policy_version: 2
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 2
`), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "diff", left, right}, &stdout, &stderr); code == 0 {
		t.Fatalf("expected non-zero exit when policies differ, stdout=%s", stdout.String())
	}
	if stdout.Len() == 0 {
		t.Fatalf("expected diff output, stderr=%s", stderr.String())
	}
}
