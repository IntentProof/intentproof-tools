package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReferenceForkEnrichesFixtureEvidenceActions(t *testing.T) {
	root := writeEnrichReferencePack(t)
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", root)
	dest := filepath.Join(t.TempDir(), "enriched")
	var stdout, stderr strings.Builder
	if code := run([]string{
		"reference", "fork", "reference.payments.refund-enrich.v1",
		"--to", dest,
		"--tenant", "tnt_enrich",
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("fork: %s", stderr.String())
	}
	flow, err := os.ReadFile(filepath.Join(dest, "fixtures", "evidence", "flow.json"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(flow)
	if !strings.Contains(text, "payments.refund.execute") {
		t.Fatalf("flow not enriched: %s", text)
	}
}

func writeEnrichReferencePack(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "reference-policies")
	packDir := filepath.Join(root, "payments", "refund-enrich", "v1")
	fixDir := filepath.Join(packDir, "fixtures", "evidence")
	if err := os.MkdirAll(fixDir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		filepath.Join(packDir, "pack.json"): `{
  "reference_id": "reference.payments.refund-enrich.v1",
  "domain": "payments",
  "name": "refund-enrich",
  "version": 1,
  "display_name": "Enrich",
  "summary": "Fork enrich coverage.",
  "policy_yaml": "policy.yaml",
  "policy": "policy.json"
}`,
		filepath.Join(packDir, "policy.yaml"): `policy_id: reference.payments.refund-enrich.v1
tenant_id: reference
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.refund.execute
rules:
  - id: req-pay
    category: required
    severity: high
    spec:
      action: payments.refund.execute
      min: 1
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
policy_fingerprint: sha256:placeholder
`,
		filepath.Join(fixDir, "flow.json"): `{
  "flow_id": "flow_enrich",
  "tenant_id": "reference",
  "flow_merkle_root": "sha256:00",
  "events": [
    {"event_id": "evt_a", "action": "placeholder.a", "status": "ok", "started_at": "2026-05-16T00:00:00Z", "completed_at": "2026-05-16T00:00:01Z"},
    {"event_id": "evt_b", "action": "placeholder.b", "status": "ok", "started_at": "2026-05-16T00:00:02Z", "completed_at": "2026-05-16T00:00:03Z"},
    {"event_id": "evt_c", "action": "placeholder.c", "status": "ok", "started_at": "2026-05-16T00:00:04Z", "completed_at": "2026-05-16T00:00:05Z"}
  ]
}`,
		filepath.Join(fixDir, "attestations.jsonl"): "",
		filepath.Join(fixDir, "expected-run.json"): `{
  "findings": [
    {"rule_id": "req-pay", "reason": "pass.required.satisfied", "evidence_event_ids": ["evt_a"]},
    {"rule_id": "order-ledger", "reason": "pass.ordering.satisfied", "evidence_event_ids": ["evt_a", "evt_b"]},
    {"rule_id": "temp-notify", "reason": "fail.temporal.exceeded_max", "evidence_event_ids": ["evt_a", "evt_c"]}
  ]
}`,
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
