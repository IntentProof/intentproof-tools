package policy

import "testing"

func TestCompileRuleRequiredMaxValidation(t *testing.T) {
	raw := []byte(`
policy_id: tnt_req.demo
tenant_id: tnt_req
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 2
    max: 1
`)
	if _, err := Compile(raw); err == nil {
		t.Fatal("expected min/max validation error")
	}
}

func TestCompileRuleForbiddenBothPredecessorForms(t *testing.T) {
	raw := []byte(`
policy_id: tnt_fb.demo
tenant_id: tnt_fb
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: forbidden
    action: bad.action
    after: pay
    where_predecessor:
      action: pay
    without_predecessor: pay
`)
	if _, err := Compile(raw); err == nil {
		t.Fatal("expected predecessor conflict error")
	}
}

func TestCompileRuleForbiddenPredecessorNeedsAfter(t *testing.T) {
	raw := []byte(`
policy_id: tnt_fa.demo
tenant_id: tnt_fa
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: forbidden
    action: bad.action
    without_predecessor: pay
`)
	if _, err := Compile(raw); err == nil {
		t.Fatal("expected after required error")
	}
}

func TestCompileRuleCardinalityExactlyConflict(t *testing.T) {
	raw := []byte(`
policy_id: tnt_card.demo
tenant_id: tnt_card
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: cardinality
    action: demo.action
    exactly: 1
    min: 1
`)
	if _, err := Compile(raw); err == nil {
		t.Fatal("expected exactly/min conflict")
	}
}

func TestCompileRuleTemporalMissingMax(t *testing.T) {
	raw := []byte(`
policy_id: tnt_temp.demo
tenant_id: tnt_temp
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
    min: PT1S
`)
	if _, err := Compile(raw); err == nil {
		t.Fatal("expected temporal max error")
	}
}

func TestCompileRuleConsensusMissingThreshold(t *testing.T) {
	raw := []byte(`
policy_id: tnt_con.demo
tenant_id: tnt_con
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: consensus
    claim: mode
    sources:
      - kind: internal
        action: pay
`)
	if _, err := Compile(raw); err == nil {
		t.Fatal("expected threshold error")
	}
}

func TestCompileRuleValueBoundUnsupportedOperator(t *testing.T) {
	raw := []byte(`
policy_id: tnt_vb.demo
tenant_id: tnt_vb
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: value_bound
    claim: amount
    operator: between
    value: 1
`)
	if _, err := Compile(raw); err == nil {
		t.Fatal("expected operator error")
	}
}

func TestCompileRuleClaimMatchConflictingRequireSigned(t *testing.T) {
	raw := []byte(`
policy_id: tnt_cm.demo
tenant_id: tnt_cm
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: claim_match
    claim: mode
    expected_value: full
    require_signed: true
    require_signed_sources: false
`)
	if _, err := Compile(raw); err == nil {
		t.Fatal("expected require_signed conflict")
	}
}

func TestCompileRuleWithExplicitSpecMap(t *testing.T) {
	raw := []byte(`
policy_id: tnt_spec.demo
tenant_id: tnt_spec
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    category: required
    severity: high
    spec:
      action: demo.action
      min: 1
      where:
        status: ok
`)
	result, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Policy.Rules) != 1 || result.Policy.Rules[0].Spec["where"] == nil {
		t.Fatalf("rules=%+v", result.Policy.Rules)
	}
}

func TestCompileRuleUsesTypeAliasForCategory(t *testing.T) {
	raw := []byte(`
policy_id: tnt_type.demo
tenant_id: tnt_type
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: ordering
    before: ship
    after: pay
`)
	result, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if result.Policy.Rules[0].Category != "ordering" {
		t.Fatalf("category=%s", result.Policy.Rules[0].Category)
	}
}
