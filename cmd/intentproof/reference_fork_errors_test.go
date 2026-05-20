package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/policy"
)

func TestStampPolicyYAMLInvalidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(":\n\tbad"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := stampPolicyYAML(path, "tnt_x")
	if err == nil || !strings.Contains(err.Error(), "parse policy yaml") {
		t.Fatalf("err=%v", err)
	}
}

func TestEnrichForkedFixtureMissingExpected(t *testing.T) {
	dir := t.TempDir()
	err := enrichForkedFixture(dir, &policy.CompileResult{})
	if err == nil {
		t.Fatal("expected missing expected-run.json")
	}
}

func TestEnrichForkedFixtureInvalidExpectedJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "expected-run.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := enrichForkedFixture(dir, &policy.CompileResult{})
	if err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("err=%v", err)
	}
}

func TestUpdateJSONFileInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flow.json")
	if err := os.WriteFile(path, []byte("not-json"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := updateJSONFile(path, func(map[string]any) {})
	if err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("err=%v", err)
	}
}

func TestRegenerateExpectedRunsVerifyError(t *testing.T) {
	root := t.TempDir()
	fixDir := filepath.Join(root, "fixtures", "bad")
	if err := os.MkdirAll(fixDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixDir, "flow.json"), []byte(`{`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixDir, "attestations.jsonl"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`
policy_id: tnt_bad.demo
tenant_id: tnt
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 1
`)
	compiled, err := policy.Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := regenerateExpectedRuns(root, compiled); err == nil {
		t.Fatal("expected verify error")
	}
}

func TestEnrichForkedFixturesNoFixtureDirs(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "fixtures"), 0o755); err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.Compile([]byte(`
policy_id: tnt_empty.demo
tenant_id: tnt
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
	if err != nil {
		t.Fatal(err)
	}
	if err := enrichForkedFixtures(filepath.Join(root, "fixtures"), compiled); err == nil {
		t.Fatal("expected no fixture directories error")
	}
}

func TestTenantPolicyIDVariants(t *testing.T) {
	if got := tenantPolicyID("reference.refund", "tnt_a"); got != "tnt_a.refund" {
		t.Fatalf("reference prefix: %q", got)
	}
	if got := tenantPolicyID("", "tnt_b"); got != "tnt_b.policy" {
		t.Fatalf("empty reference: %q", got)
	}
	if got := tenantPolicyID("custom.id", "tnt_c"); got != "tnt_c.custom.id" {
		t.Fatalf("custom: %q", got)
	}
}

func TestEnrichForkedFixtureTemporalOffsets(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fixture")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "flow.json"), []byte(`{
  "flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0",
  "events":[
    {"event_id":"evt_from","action":"placeholder","status":"ok",
      "started_at":"2020-01-01T00:00:00Z","completed_at":"2020-01-01T00:00:01Z"},
    {"event_id":"evt_to","action":"placeholder","status":"ok",
      "started_at":"2020-01-01T00:00:00Z","completed_at":"2020-01-01T00:00:01Z"}
  ]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "expected-run.json"), []byte(`{
  "findings":[
    {"rule_id":"temp","reason":"fail.temporal.exceeded","evidence_event_ids":["evt_from","evt_to"]}
  ]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.Compile([]byte(`
policy_id: tnt_temp.demo
tenant_id: tnt
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: pay.run
rules:
  - id: temp
    category: temporal
    severity: medium
    spec:
      from: { action: pay.run }
      to: { action: notify.run }
      max: PT5M
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := enrichForkedFixture(dir, compiled); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "flow.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "pay.run") || !strings.Contains(string(raw), "notify.run") {
		t.Fatalf("flow=%s", raw)
	}
}

func TestAssignEvidenceActionsOrderingAndCardinality(t *testing.T) {
	out := map[string]string{}
	assignEvidenceActions(policy.CanonicalRule{
		Category: "ordering",
		Spec:     map[string]any{"before": "b", "after": "a"},
	}, []string{"e1", "e2"}, out)
	if out["e1"] != "b" || out["e2"] != "a" {
		t.Fatalf("ordering=%v", out)
	}
	out2 := map[string]string{}
	assignEvidenceActions(policy.CanonicalRule{
		Category: "cardinality",
		Spec:     map[string]any{"action": "card.action"},
	}, []string{"e3"}, out2)
	if out2["e3"] != "card.action" {
		t.Fatalf("cardinality=%v", out2)
	}
}

func TestWriteCanonicalPolicyJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	compiled, err := policy.Compile([]byte(`
policy_id: tnt_write.demo
tenant_id: tnt
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
	if err != nil {
		t.Fatal(err)
	}
	if err := writeCanonicalPolicyJSON(path, compiled); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
