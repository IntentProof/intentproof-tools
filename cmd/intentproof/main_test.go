package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyLintCommand(t *testing.T) {
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	content := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
`
	if err := os.WriteFile(policyPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder

	code := run([]string{"policy", "lint", policyPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected code 0, got %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "fingerprint: sha256:") {
		t.Fatalf("expected fingerprint output, got %s", stdout.String())
	}
}

func TestPolicyLintCommandMissingFile(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder

	code := run([]string{"policy", "lint", "missing.yaml"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero code")
	}
	if !strings.Contains(stderr.String(), "lint failed") {
		t.Fatalf("expected lint failed output, got %s", stderr.String())
	}
}

func TestPolicyTestCommandGeneratesGolden(t *testing.T) {
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	fixturesDir := filepath.Join(tmp, "fixtures", "happy-path")
	if err := os.MkdirAll(fixturesDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	policyYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
`
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o644); err != nil {
		t.Fatalf("WriteFile policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fixturesDir, "flow.json"), []byte(`{"events":[]}`), 0o644); err != nil {
		t.Fatalf("WriteFile flow: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fixturesDir, "attestations.jsonl"), []byte(""), 0o644); err != nil {
		t.Fatalf("WriteFile attestation: %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"policy", "test", tmp}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected code 0, got %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "1 fixtures, 1 passed, 1 generated") {
		t.Fatalf("unexpected output: %s", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(fixturesDir, "expected-run.json")); err != nil {
		t.Fatalf("expected-run.json not created: %v", err)
	}
}

func TestPolicyTestCommandDetectsMismatch(t *testing.T) {
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	fixturesDir := filepath.Join(tmp, "fixtures", "bad")
	if err := os.MkdirAll(fixturesDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	policyYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
`
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o644); err != nil {
		t.Fatalf("WriteFile policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fixturesDir, "flow.json"), []byte(`{"events":[]}`), 0o644); err != nil {
		t.Fatalf("WriteFile flow: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fixturesDir, "attestations.jsonl"), []byte(""), 0o644); err != nil {
		t.Fatalf("WriteFile attestation: %v", err)
	}

	wrongExpected := map[string]any{"status": "fail"}
	raw, _ := json.MarshalIndent(wrongExpected, "", "  ")
	if err := os.WriteFile(filepath.Join(fixturesDir, "expected-run.json"), raw, 0o644); err != nil {
		t.Fatalf("WriteFile expected: %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"policy", "test", tmp}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero for mismatch")
	}
	if !strings.Contains(stdout.String(), "run mismatch") {
		t.Fatalf("expected mismatch output, got %s", stdout.String())
	}
}

func TestPolicyDiffCommandIdentical(t *testing.T) {
	tmp := t.TempDir()
	leftPath := filepath.Join(tmp, "left.yaml")
	rightPath := filepath.Join(tmp, "right.yaml")
	content := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
`
	if err := os.WriteFile(leftPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile left: %v", err)
	}
	if err := os.WriteFile(rightPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile right: %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"policy", "diff", leftPath, rightPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected code 0 for identical policies, got %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "semantically identical") {
		t.Fatalf("expected identical message, got %s", stdout.String())
	}
}

func TestPolicyDiffCommandDetectsChange(t *testing.T) {
	tmp := t.TempDir()
	leftPath := filepath.Join(tmp, "left.yaml")
	rightPath := filepath.Join(tmp, "right.yaml")
	leftContent := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
`
	rightContent := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 2
`
	if err := os.WriteFile(leftPath, []byte(leftContent), 0o644); err != nil {
		t.Fatalf("WriteFile left: %v", err)
	}
	if err := os.WriteFile(rightPath, []byte(rightContent), 0o644); err != nil {
		t.Fatalf("WriteFile right: %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"policy", "diff", leftPath, rightPath}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero code for differing policies")
	}
	out := stdout.String()
	if !strings.Contains(out, "~ r1") {
		t.Fatalf("expected ~ r1 in output, got %s", out)
	}
	if !strings.Contains(out, "~ min:") {
		t.Fatalf("expected min change in output, got %s", out)
	}
	if !strings.Contains(out, "old fingerprint:") {
		t.Fatalf("expected old fingerprint in output, got %s", out)
	}
	if !strings.Contains(out, "new fingerprint:") {
		t.Fatalf("expected new fingerprint in output, got %s", out)
	}
}

func TestPolicyDiffCommandMissingArgs(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"policy", "diff", "left.yaml"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero code")
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("expected usage output, got %s", stderr.String())
	}
}

func TestPolicyDiffCommandBadCompile(t *testing.T) {
	tmp := t.TempDir()
	leftPath := filepath.Join(tmp, "left.yaml")
	if err := os.WriteFile(leftPath, []byte("invalid"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"policy", "diff", leftPath, leftPath}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero code")
	}
	if !strings.Contains(stderr.String(), "compile left failed") {
		t.Fatalf("expected compile left failed, got %s", stderr.String())
	}
}

func TestPolicyTestCommandOutputsFixtureOrderDeterministically(t *testing.T) {
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
`), 0o644); err != nil {
		t.Fatalf("WriteFile policy: %v", err)
	}

	for _, name := range []string{"z-last", "a-first"} {
		dir := filepath.Join(tmp, "fixtures", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "flow.json"), []byte(`{"events":[]}`), 0o644); err != nil {
			t.Fatalf("WriteFile flow: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "attestations.jsonl"), []byte(""), 0o644); err != nil {
			t.Fatalf("WriteFile attestation: %v", err)
		}
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"policy", "test", tmp}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected code 0, got %d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	idxA := strings.Index(out, "a-first")
	idxZ := strings.Index(out, "z-last")
	if idxA == -1 || idxZ == -1 {
		t.Fatalf("expected both fixture names in output, got %s", out)
	}
	if idxA > idxZ {
		t.Fatalf("expected alphabetical output order, got %s", out)
	}
}
