package policy

import "testing"

func TestCompileRuleUsesExplicitSpecBlock(t *testing.T) {
	raw := []byte(`
policy_id: tnt_spec.demo
tenant_id: tnt_spec
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    severity: high
    spec:
      action: demo.action
      min: 1
`)
	res, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Policy.Rules) != 1 || res.Policy.Rules[0].Category != "required" {
		t.Fatalf("rules=%+v", res.Policy.Rules)
	}
}

func TestCompileRuleOrderingCategory(t *testing.T) {
	raw := []byte(`
policy_id: tnt_ord.demo
tenant_id: tnt_ord
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: ordering
    before: pay
    after: ship
`)
	res, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	spec := res.Policy.Rules[0].Spec
	if spec["before"] != "pay" || spec["after"] != "ship" {
		t.Fatalf("spec=%v", spec)
	}
}

func TestCompileRuleTemporalCategory(t *testing.T) {
	raw := []byte(`
policy_id: tnt_tmp.demo
tenant_id: tnt_tmp
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: temporal
    from:
      action: pay
    to:
      action: ship
    max: "1s"
`)
	res, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Policy.Rules[0].Category != "temporal" {
		t.Fatalf("category=%s", res.Policy.Rules[0].Category)
	}
}
