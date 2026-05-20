package policy

import (
	"strings"
	"testing"
)

func TestCompileRuleRemainingValidationGaps(t *testing.T) {
	tests := []struct {
		name    string
		rules   string
		contain string
	}{
		{
			name: "missing rule category",
			rules: `  - id: r1
    severity: high
    action: demo.action`,
			contain: "rule type or category is required",
		},
		{
			name: "cardinality invalid exactly",
			rules: `  - id: r1
    type: cardinality
    action: demo.action
    exactly: bad`,
			contain: "exactly must be an integer",
		},
		{
			name: "forbidden with where",
			rules: `  - id: r1
    type: forbidden
    action: bad.action
    after: ok.action
    where:
      status: fail`,
			contain: "",
		},
		{
			name: "cardinality missing action",
			rules: `  - id: r1
    type: cardinality
    min: 1`,
			contain: "cardinality rule needs action",
		},
		{
			name: "temporal missing from",
			rules: `  - id: r1
    type: temporal
    to:
      action: ship
    max: "1s"`,
			contain: "temporal rule needs from and to",
		},
		{
			name: "claim_match conflicting signed flags",
			rules: `  - id: r1
    type: claim_match
    claim: c
    expected_value: ok
    require_signed: true
    require_signed_sources: false`,
			contain: "conflicting values",
		},
		{
			name: "unknown rule category",
			rules: `  - id: r1
    type: not-a-rule
    action: demo.action`,
			contain: "unknown rule category",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.contain == "" {
				res, err := Compile(wrap(tc.rules))
				if err != nil {
					t.Fatalf("err=%v", err)
				}
				if len(res.Policy.Rules) != 1 {
					t.Fatalf("rules=%+v", res.Policy.Rules)
				}
				return
			}
			_, err := Compile(wrap(tc.rules))
			if err == nil || !strings.Contains(err.Error(), tc.contain) {
				t.Fatalf("err=%v want %q", err, tc.contain)
			}
		})
	}
}

func TestCompileConsensusNormalizesInternalSourceKind(t *testing.T) {
	raw := []byte(`
policy_id: tnt_c.demo
tenant_id: tnt_c
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: consensus
    claim: amount
    sources:
      - kind: internal
        action: demo.action
    threshold:
      unanimous: true
`)
	res, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	sources := res.Policy.Rules[0].Spec["sources"].([]map[string]interface{})
	if len(sources) == 0 || sources[0]["kind"] != "intentproof_action" {
		t.Fatalf("sources=%v", sources)
	}
}

func TestCompileClaimMatchUsesRequireSignedAliasField(t *testing.T) {
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
    claim: status
    expected_value: ok
    require_signed_sources: true
`)
	res, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Policy.Rules[0].Spec["require_signed"] != true {
		t.Fatalf("spec=%v", res.Policy.Rules[0].Spec)
	}
}
