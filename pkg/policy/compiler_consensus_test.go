package policy

import "testing"

func TestCompileRuleWithCategoryFieldAlias(t *testing.T) {
	raw := []byte(`
policy_id: tnt_cat.demo
tenant_id: tnt_cat
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    category: forbidden
    action: bad.action
`)
	res, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Policy.Rules[0].Category != "forbidden" {
		t.Fatalf("category=%s", res.Policy.Rules[0].Category)
	}
}

func TestCompileRuleExplicitSpecPreservesSeverity(t *testing.T) {
	raw := []byte(`
policy_id: tnt_sev.demo
tenant_id: tnt_sev
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    severity: critical
    spec:
      action: demo.action
      min: 1
`)
	res, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Policy.Rules[0].Severity != "critical" {
		t.Fatalf("severity=%s", res.Policy.Rules[0].Severity)
	}
}
