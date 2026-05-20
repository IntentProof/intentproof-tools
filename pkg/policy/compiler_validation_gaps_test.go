package policy

import (
	"strings"
	"testing"
)

func TestCompileRuleValidationGaps(t *testing.T) {
	tests := []struct {
		name    string
		rules   string
		contain string
	}{
		{
			name: "forbidden both predecessor forms",
			rules: `  - id: r1
    type: forbidden
    action: bad.action
    after: ok.action
    without_predecessor: ok.action
    where_predecessor:
      action: ok.action`,
			contain: "cannot set both where_predecessor and without_predecessor",
		},
		{
			name: "forbidden missing after with predecessor",
			rules: `  - id: r1
    type: forbidden
    action: bad.action
    without_predecessor: ok.action`,
			contain: "requires after",
		},
		{
			name: "cardinality exactly conflicts with min",
			rules: `  - id: r1
    type: cardinality
    action: demo.action
    exactly: 1
    min: 1`,
			contain: "exactly conflicts with min/max",
		},
		{
			name: "consensus missing claim",
			rules: `  - id: r1
    type: consensus
    sources:
      - kind: internal
        action: demo.action
    threshold:
      unanimous: true`,
			contain: "consensus rule needs claim",
		},
		{
			name: "consensus missing threshold",
			rules: `  - id: r1
    type: consensus
    claim: amount
    sources:
      - kind: internal
        action: demo.action`,
			contain: "consensus rule needs threshold",
		},
		{
			name: "value_bound missing claim",
			rules: `  - id: r1
    type: value_bound
    operator: gt
    value: 1`,
			contain: "value_bound rule needs claim",
		},
		{
			name: "value_bound missing operator",
			rules: `  - id: r1
    type: value_bound
    claim: amount
    value: 1`,
			contain: "value_bound rule needs operator",
		},
		{
			name: "value_bound non numeric value",
			rules: `  - id: r1
    type: value_bound
    claim: amount
    operator: gt
    value: not-a-number`,
			contain: "value_bound rule needs numeric value",
		},
		{
			name: "claim_match missing claim",
			rules: `  - id: r1
    type: claim_match
    expected_value: ok`,
			contain: "claim_match rule needs claim",
		},
		{
			name: "cardinality invalid max",
			rules: `  - id: r1
    type: cardinality
    action: demo.action
    max: bad`,
			contain: "max must be an integer",
		},
		{
			name: "required invalid min",
			rules: `  - id: r1
    type: required
    action: demo.action
    min: bad`,
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
