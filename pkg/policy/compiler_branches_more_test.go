package policy

import (
	"strings"
	"testing"
)

func TestCompileForbiddenRuleBranches(t *testing.T) {
	raw := wrap(`  - id: f1
    type: forbidden
    action: bad.action
    after: good.action
    where_predecessor: { status: ok }
    without_predecessor: other
`)
	_, err := Compile(raw)
	if err == nil || !strings.Contains(err.Error(), "cannot set both") {
		t.Fatalf("err=%v", err)
	}

	raw2 := wrap(`  - id: f2
    type: forbidden
    action: bad.action
    where_predecessor: { status: ok }
`)
	_, err = Compile(raw2)
	if err == nil || !strings.Contains(err.Error(), "requires after") {
		t.Fatalf("err=%v", err)
	}
}

func TestCompileCardinalityExactlyConflict(t *testing.T) {
	raw := wrap(`  - id: c1
    type: cardinality
    action: demo.action
    exactly: 1
    min: 1
`)
	_, err := Compile(raw)
	if err == nil || !strings.Contains(err.Error(), "exactly conflicts") {
		t.Fatalf("err=%v", err)
	}
}

func TestCompileDuplicateRuleID(t *testing.T) {
	raw := wrap(`  - id: dup
    type: required
    action: demo.action
    min: 1
  - id: dup
    type: required
    action: demo.action
    min: 1
`)
	_, err := Compile(raw)
	if err == nil || !strings.Contains(err.Error(), "duplicate rule id") {
		t.Fatalf("err=%v", err)
	}
}

func TestCompileRuleFromSpecOnly(t *testing.T) {
	raw := wrap(`  - id: spec_only
    category: required
    severity: low
    spec:
      action: demo.action
      min: 1
`)
	res, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Policy.Rules) != 1 || res.Policy.Rules[0].ID != "spec_only" {
		t.Fatalf("rules=%+v", res.Policy.Rules)
	}
}

func TestCompileCategoryFromTypeField(t *testing.T) {
	raw := wrap(`  - id: t1
    type: required
    action: demo.action
    min: 1
`)
	res, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Policy.Rules[0].Category != "required" {
		t.Fatalf("category=%s", res.Policy.Rules[0].Category)
	}
}

func TestCompileClaimMatchRequireSignedConflict(t *testing.T) {
	raw := wrap(`  - id: cm
    type: claim_match
    claim: refund.ok
    expected_value: true
    require_signed: true
    require_signed_sources: false
`)
	_, err := Compile(raw)
	if err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("err=%v", err)
	}

	raw2 := wrap(`  - id: cm2
    type: claim_match
    claim: refund.ok
    expected_value: true
    require_signed: true
`)
	res, err := Compile(raw2)
	if err != nil {
		t.Fatal(err)
	}
	if res.Policy.Rules[0].Spec["require_signed"] != true {
		t.Fatalf("spec=%v", res.Policy.Rules[0].Spec)
	}
}

func TestCompileTemporalWithMinString(t *testing.T) {
	raw := wrap(`  - id: temp
    type: temporal
    from: { action: a }
    to: { action: b }
    min: PT1S
    max: PT5M
`)
	res, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Policy.Rules[0].Spec["min"] != "PT1S" {
		t.Fatalf("spec=%v", res.Policy.Rules[0].Spec)
	}
}

func TestCompileConsensusInternalKindRewrite(t *testing.T) {
	raw := wrap(`  - id: cons
    type: consensus
    claim: c
    sources:
      - kind: internal
        action: demo.action
    threshold:
      majority: true
`)
	res, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	sources, ok := res.Policy.Rules[0].Spec["sources"].([]map[string]any)
	if !ok || len(sources) == 0 {
		t.Fatalf("sources=%v", res.Policy.Rules[0].Spec["sources"])
	}
	if sources[0]["kind"] != "intentproof_action" {
		t.Fatalf("kind=%v", sources[0]["kind"])
	}
}

func TestCompileValidateMinMaxNegative(t *testing.T) {
	if err := validateMinMax(intPtr(-1), intPtr(2)); err == nil {
		t.Fatal("expected min error")
	}
	if err := validateMinMax(intPtr(0), intPtr(-1)); err == nil {
		t.Fatal("expected max error")
	}
	if err := validateMinMax(intPtr(5), intPtr(1)); err == nil {
		t.Fatal("expected range error")
	}
}

func TestCompileValidateThresholdAgreeAtLeastTypes(t *testing.T) {
	if err := validateThreshold(map[string]any{"agree_at_least": int64(0)}); err == nil {
		t.Fatal("int64 zero")
	}
	if err := validateThreshold(map[string]any{"agree_at_least": float64(0.5)}); err == nil {
		t.Fatal("float fractional")
	}
	if err := validateThreshold(map[string]any{"agree_at_least": "x"}); err == nil {
		t.Fatal("non-numeric")
	}
	if err := validateThreshold(map[string]any{"majority": false}); err == nil {
		t.Fatal("majority false")
	}
}

func TestCompileScopeDedupesActions(t *testing.T) {
	raw := []byte(`
policy_id: tnt_scope.demo
tenant_id: tnt_scope
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
  any_event_action_in:
    - demo.action
    - ""
rules:
  - id: r1
    type: required
    action: demo.action
    min: 1
`)
	res, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Policy.Scope.AnyEventActionIn) != 1 {
		t.Fatalf("scope=%v", res.Policy.Scope.AnyEventActionIn)
	}
}

func intPtr(v int) *int { return &v }
