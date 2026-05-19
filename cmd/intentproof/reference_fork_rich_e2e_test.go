package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReferenceForkRichPackRegeneratesFixtures(t *testing.T) {
	referenceRoot := writeRichReferencePack(t)
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", referenceRoot)

	dest := filepath.Join(t.TempDir(), "policies", "rich-refund")
	var stdout, stderr strings.Builder
	code := run([]string{
		"reference", "fork", "reference.payments.refund-rich.v1",
		"--to", dest,
		"--tenant", "tnt_rich",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("fork failed: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"policy", "test", dest}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("policy test failed: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "passed") {
		t.Fatalf("stdout=%s", stdout.String())
	}

	policyYAML, err := os.ReadFile(filepath.Join(dest, "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(policyYAML), "tenant_id: tnt_rich") {
		t.Fatalf("policy.yaml missing tenant stamp")
	}
}

func writeRichReferencePack(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "reference-policies")
	packDir := filepath.Join(root, "payments", "refund-rich", "v1")
	fixtureDir := filepath.Join(packDir, "fixtures", "temporal-fail")
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		t.Fatal(err)
	}

	files := map[string]string{
		filepath.Join(packDir, "pack.json"): `{
  "reference_id": "reference.payments.refund-rich.v1",
  "domain": "payments",
  "name": "refund-rich",
  "version": 1,
  "display_name": "Refund rich",
  "summary": "Ordering and temporal rules.",
  "policy_yaml": "policy.yaml",
  "policy": "policy.json"
}`,
		filepath.Join(packDir, "policy.yaml"): `policy_id: reference.payments.refund-rich.v1
tenant_id: reference
policy_version: 1
name: Refund rich
spec_version: 1.0.0
scope:
  any_event_action_in:
    - payments.refund.execute
    - ledger.entry.write
    - customer.notify
rules:
  - id: ordering-refund
    category: ordering
    severity: high
    spec:
      before: payments.refund.execute
      after: ledger.entry.write
  - id: temporal-notify
    category: temporal
    severity: high
    spec:
      from:
        action: payments.refund.execute
      to:
        action: customer.notify
      max: PT5M
policy_fingerprint: sha256:placeholder
`,
		filepath.Join(fixtureDir, "flow.json"): `{
  "flow_id": "flow_rich",
  "tenant_id": "reference",
  "flow_merkle_root": "sha256:0000",
  "events": [
    {"event_id": "evt_refund", "action": "payments.refund.execute", "status": "ok", "started_at": "2026-05-16T00:00:00Z", "completed_at": "2026-05-16T00:00:01Z"},
    {"event_id": "evt_notify", "action": "customer.notify", "status": "ok", "started_at": "2026-05-16T01:00:00Z", "completed_at": "2026-05-16T01:00:01Z"}
  ]
}
`,
		filepath.Join(fixtureDir, "attestations.jsonl"): "",
		filepath.Join(fixtureDir, "expected-run.json"): `{
  "findings": [
    {
      "rule_id": "temporal-notify",
      "reason": "fail.temporal.exceeded",
      "evidence_event_ids": ["evt_refund", "evt_notify"]
    }
  ]
}
`,
	}
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
