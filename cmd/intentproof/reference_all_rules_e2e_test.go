package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReferenceListAndForkAllRuleCategories(t *testing.T) {
	root := writeAllRulesReferencePack(t)
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", root)

	var stdout, stderr strings.Builder
	if code := run([]string{"reference", "list"}, &stdout, &stderr); code != 0 {
		t.Fatalf("list: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "refund-all-rules") {
		t.Fatalf("stdout=%s", stdout.String())
	}

	dest := filepath.Join(t.TempDir(), "tenant-pack")
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"reference", "fork", "reference.payments.refund-all-rules.v1",
		"--to", dest,
		"--tenant", "tnt_all",
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("fork: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"policy", "test", dest}, &stdout, &stderr); code != 0 {
		t.Fatalf("policy test: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func writeAllRulesReferencePack(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "reference-policies")
	packDir := filepath.Join(root, "payments", "refund-all-rules", "v1")
	fixDir := filepath.Join(packDir, "fixtures", "mixed")
	if err := os.MkdirAll(fixDir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		filepath.Join(packDir, "pack.json"): `{
  "reference_id": "reference.payments.refund-all-rules.v1",
  "domain": "payments",
  "name": "refund-all-rules",
  "version": 1,
  "display_name": "All rules",
  "summary": "Every rule category for fork enrich.",
  "policy_yaml": "policy.yaml",
  "policy": "policy.json"
}`,
		filepath.Join(packDir, "policy.yaml"): `policy_id: reference.payments.refund-all-rules.v1
tenant_id: reference
policy_version: 1
name: All rules
spec_version: 1.0.0
scope:
  match_action: "*"
rules:
  - id: req-pay
    category: required
    severity: high
    spec:
      action: payments.refund.execute
  - id: forbid-bad
    category: forbidden
    severity: high
    spec:
      action: payments.fraud.execute
  - id: card-notify
    category: cardinality
    severity: medium
    spec:
      action: customer.notify
      max: 2
  - id: order-ledger
    category: ordering
    severity: high
    spec:
      before: payments.refund.execute
      after: ledger.entry.write
  - id: temp-notify
    category: temporal
    severity: high
    spec:
      from:
        action: payments.refund.execute
      to:
        action: customer.notify
      max: PT10M
  - id: consensus-src
    category: consensus
    severity: high
    spec:
      sources:
        - payments.refund.execute
      agree_at_least: 1
policy_fingerprint: sha256:placeholder
`,
		filepath.Join(fixDir, "flow.json"): `{
  "flow_id": "flow_all",
  "tenant_id": "reference",
  "flow_merkle_root": "sha256:00",
  "events": [
    {"event_id": "evt_pay", "action": "payments.refund.execute", "status": "ok", "started_at": "2026-05-16T00:00:00Z", "completed_at": "2026-05-16T00:00:01Z"},
    {"event_id": "evt_ledger", "action": "ledger.entry.write", "status": "ok", "started_at": "2026-05-16T00:00:02Z", "completed_at": "2026-05-16T00:00:03Z"},
    {"event_id": "evt_notify", "action": "customer.notify", "status": "ok", "started_at": "2026-05-16T00:00:04Z", "completed_at": "2026-05-16T00:00:05Z"}
  ]
}`,
		filepath.Join(fixDir, "attestations.jsonl"): "",
		filepath.Join(fixDir, "expected-run.json"):  `{"findings":[]}`,
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
