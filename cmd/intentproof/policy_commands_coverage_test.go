package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/policy"
)

func TestRunOneFixtureVerifyPolicyError(t *testing.T) {
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
	_, _, err := runOneFixture(dir, []byte(`{`))
	if err == nil {
		t.Fatal("expected verify error")
	}
}

func TestJsonEqualIgnoreTimestampsNonObjectFallback(t *testing.T) {
	if !jsonEqualIgnoreTimestamps([]int{1}, []int{1}) {
		t.Fatal("expected slice equality")
	}
	if jsonEqualIgnoreTimestamps([]int{1}, []int{2}) {
		t.Fatal("expected slice inequality")
	}
}

func TestMaybeSignPolicySignFailure(t *testing.T) {
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "")
	seed := make([]byte, ed25519.SeedSize)
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", base64.StdEncoding.EncodeToString(seed))
	compiled, err := policyCompileMinimalForSign(t)
	if err != nil {
		t.Fatal(err)
	}
	_, err = maybeSignPolicy(compiled)
	if err == nil {
		t.Fatal("expected sign failure with invalid seed-only key")
	}
}

func TestRunPolicyActivateTenantIDFlagMissingValue(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runPolicyActivate([]string{"tnt_x.demo", "1", "--scope", "global", "--tenant-id"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected missing tenant-id value error")
	}
	if !strings.Contains(stderr.String(), "--tenant-id requires a value") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestRunPolicyActivateNetworkError(t *testing.T) {
	t.Setenv("INTENTPROOF_QUERY_API_URL", "http://127.0.0.1:1")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "activate", "tnt_x.demo", "1", "--scope", "global"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected activate failure")
	}
}

func policyCompileMinimalForSign(t *testing.T) (*policy.CompileResult, error) {
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
