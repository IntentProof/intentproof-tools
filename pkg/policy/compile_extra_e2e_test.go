package policy

import "testing"

func TestCompileValueBoundAndClaimMatchRules(t *testing.T) {
	raw := []byte(`
policy_id: tnt.test
tenant_id: tnt
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: "*"
rules:
  - id: vb1
    type: value_bound
    claim: risk.score
    operator: lte
    value: 0.9
  - id: cm1
    type: claim_match
    claim: refund.ok
    expected_value: true
`)
	result, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Policy.Rules) != 2 {
		t.Fatalf("rules=%d", len(result.Policy.Rules))
	}
}
