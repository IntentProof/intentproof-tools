package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/policy"
)

func TestRunOneFixtureReadFlowError(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fixture")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "attestations.jsonl"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := runOneFixture(dir, []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]}`))
	if err == nil {
		t.Fatal("expected read flow error")
	}
}

func TestRunOneFixtureParseExpectedError(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(dir, "expected-run.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := runOneFixture(dir, []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]}`))
	if err == nil {
		t.Fatal("expected parse expected-run error")
	}
}

func TestMaybeSignPolicyInitSignerError(t *testing.T) {
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "bad-key")
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", "")
	compiled, err := policyCompileMinimal(t)
	if err != nil {
		t.Fatal(err)
	}
	_, err = maybeSignPolicy(compiled)
	if err == nil {
		t.Fatal("expected init signer error")
	}
}

func policyCompileMinimal(t *testing.T) (*policy.CompileResult, error) {
	t.Helper()
	return policy.Compile([]byte(`
policy_id: tnt_min.demo
tenant_id: tnt_min
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
}
