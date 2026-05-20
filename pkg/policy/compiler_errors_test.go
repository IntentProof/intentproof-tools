package policy

import (
	"strings"
	"testing"
)

func TestCompileRuleCategoryErrors(t *testing.T) {
	tests := []struct {
		name    string
		rules   string
		contain string
	}{
		{
			name: "required missing action",
			rules: `  - id: r1
    type: required
    min: 1`,
			contain: "required rule needs action",
		},
		{
			name: "ordering missing after",
			rules: `  - id: r1
    type: ordering
    before: a`,
			contain: "ordering rule needs before and after",
		},
		{
			name: "temporal missing max",
			rules: `  - id: r1
    type: temporal
    from: { action: a }
    to: { action: b }`,
			contain: "temporal rule needs max duration",
		},
		{
			name: "consensus missing sources",
			rules: `  - id: r1
    type: consensus
    claim: c
    threshold:
      unanimous: true`,
			contain: "consensus rule needs sources",
		},
		{
			name: "value_bound bad operator",
			rules: `  - id: r1
    type: value_bound
    claim: c
    operator: between
    value: 1`,
			contain: "unsupported operator",
		},
		{
			name: "claim_match missing expected",
			rules: `  - id: r1
    type: claim_match
    claim: c`,
			contain: "claim_match rule needs expected_value",
		},
		{
			name: "int field fractional",
			rules: `  - id: r1
    type: required
    action: demo.action
    min: 1.5`,
			contain: "min must be an integer",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile(wrap(tc.rules))
			if err == nil || !strings.Contains(err.Error(), tc.contain) {
				t.Fatalf("err=%v want %q", err, tc.contain)
			}
		})
	}
}

func TestCompileDerivesTenantFromPolicyID(t *testing.T) {
	raw := []byte(`
policy_id: tnt_acme.flow
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
	res, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Policy.TenantID != "tnt_acme" {
		t.Fatalf("tenant=%s", res.Policy.TenantID)
	}
}

func TestCompileRejectsNoRules(t *testing.T) {
	raw := []byte(`
policy_id: tnt.test
tenant_id: tnt
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules: []
`)
	if _, err := Compile(raw); err == nil || !strings.Contains(err.Error(), "at least one rule") {
		t.Fatalf("err=%v", err)
	}
}

func TestValidateThresholdErrors(t *testing.T) {
	if err := validateThreshold(map[string]any{"unanimous": false}); err == nil {
		t.Fatal("unanimous false")
	}
	if err := validateThreshold(map[string]any{}); err == nil {
		t.Fatal("empty threshold")
	}
	if err := validateThreshold(map[string]any{
		"unanimous": true, "majority": true,
	}); err == nil {
		t.Fatal("two operators")
	}
}
