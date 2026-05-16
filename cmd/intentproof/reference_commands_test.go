package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReferenceListCommand(t *testing.T) {
	referenceRoot := writeSampleReferencePack(t)
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", referenceRoot)

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"reference", "list"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected code 0, got %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "reference.payments.refund-basic.v1") {
		t.Fatalf("expected reference id in output, got %s", stdout.String())
	}
}

func TestReferenceForkCommandCreatesTestablePolicy(t *testing.T) {
	referenceRoot := writeSampleReferencePack(t)
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", referenceRoot)

	dest := filepath.Join(t.TempDir(), "policies", "refund-basic")
	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{
		"reference", "fork", "reference.payments.refund-basic.v1",
		"--to", dest,
		"--tenant", "tnt_acme",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected code 0, got %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "forked reference.payments.refund-basic.v1") {
		t.Fatalf("unexpected output: %s", stdout.String())
	}

	policyYAML, err := os.ReadFile(filepath.Join(dest, "policy.yaml"))
	if err != nil {
		t.Fatalf("ReadFile policy.yaml: %v", err)
	}
	policyText := string(policyYAML)
	if !strings.Contains(policyText, "tenant_id: tnt_acme") {
		t.Fatalf("expected tenant stamp, got %s", policyText)
	}
	if !strings.Contains(policyText, "policy_id: tnt_acme.payments.refund-basic.v1") {
		t.Fatalf("expected tenant policy id, got %s", policyText)
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"policy", "test", dest}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected forked policy tests to pass, got %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "1 fixtures, 1 passed") {
		t.Fatalf("unexpected policy test output: %s", stdout.String())
	}
}

func writeSampleReferencePack(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "reference-policies")
	packDir := filepath.Join(root, "payments", "refund-basic", "v1")
	fixtureDir := filepath.Join(packDir, "fixtures", "happy-path")
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	files := map[string]string{
		filepath.Join(packDir, "pack.json"): `{
  "reference_id": "reference.payments.refund-basic.v1",
  "domain": "payments",
  "name": "refund-basic",
  "version": 1,
  "display_name": "Refund basic",
  "summary": "Requires a refund event.",
  "policy": "policy.json",
  "policy_yaml": "policy.yaml",
  "migration_notes": "MIGRATION.md"
}
`,
		filepath.Join(packDir, "policy.json"): `{
  "policy_id": "reference.payments.refund-basic.v1",
  "tenant_id": "reference"
}
`,
		filepath.Join(packDir, "policy.yaml"): `policy_id: reference.payments.refund-basic.v1
tenant_id: reference
policy_version: 1
name: Refund basic
spec_version: 1.0.0
scope:
  any_event_action_in:
    - payments.refund.create
rules:
  - id: required-refund-created
    category: required
    severity: high
    spec:
      action: payments.refund.create
      min: 1
      where:
        status: ok
policy_fingerprint: sha256:placeholder
`,
		filepath.Join(packDir, "README.md"):             "# Refund basic\n",
		filepath.Join(packDir, "MIGRATION.md"):          "# Migration\n",
		filepath.Join(fixtureDir, "flow.json"):          `{"flow_id":"flow_refund_basic","tenant_id":"reference","flow_merkle_root":"sha256:0000","events":[{"event_id":"evt_refund_created"}]}` + "\n",
		filepath.Join(fixtureDir, "attestations.jsonl"): "",
		filepath.Join(fixtureDir, "expected-run.json"): `{
  "findings": [
    {
      "rule_id": "required-refund-created",
      "reason": "pass.required.met",
      "evidence_event_ids": ["evt_refund_created"]
    }
  ]
}
`,
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
	}
	return root
}
