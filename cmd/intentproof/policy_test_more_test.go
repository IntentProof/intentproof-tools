package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPolicyTestMissingFixturesDir(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "policy.yaml"), []byte(`
policy_id: tnt_miss.demo
tenant_id: tnt_miss
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
	if code := runPolicyTest([]string{root}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}

func TestRunOneFixtureMissingFlow(t *testing.T) {
	dir := t.TempDir()
	ok, gen, err := runOneFixture(dir, []byte(`{"rules":[]}`))
	if err == nil || ok || gen {
		t.Fatalf("ok=%v gen=%v err=%v", ok, gen, err)
	}
}

func TestRunOneFixtureInvalidExpectedJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "flow.json"), []byte(`{
  "flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "attestations.jsonl"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "expected-run.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := runOneFixture(dir, []byte(`{"policy_id":"p","tenant_id":"tnt","policy_version":1,"rules":[]}`))
	if err == nil || !strings.Contains(err.Error(), "parse expected-run.json") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunPolicyTestFixtureVerifyError(t *testing.T) {
	root := t.TempDir()
	fixDir := filepath.Join(root, "fixtures", "broken")
	if err := os.MkdirAll(fixDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "policy.yaml"), []byte(`
policy_id: tnt_broken.demo
tenant_id: tnt_broken
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
	if err := os.WriteFile(filepath.Join(fixDir, "flow.json"), []byte(`{`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixDir, "attestations.jsonl"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runPolicyTest([]string{root}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stdout.String(), "broken") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestRunPolicyLintUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runPolicyLint(nil, &stdout, &stderr); code == 0 {
		t.Fatal("expected usage failure")
	}
}

func TestRunPolicyTestUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runPolicyTest(nil, &stdout, &stderr); code == 0 {
		t.Fatal("expected usage failure")
	}
}

func TestRunReferenceUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runReference([]string{"nope"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}

func TestRunReferenceUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runReference(nil, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}
