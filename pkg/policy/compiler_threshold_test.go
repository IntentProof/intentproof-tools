package policy

import (
	"strings"
	"testing"
)

func TestCompileConsensusThresholdValidation(t *testing.T) {
	tests := []struct {
		name    string
		rules   string
		contain string
	}{
		{
			name: "unanimous must be true",
			rules: `  - id: r1
    type: consensus
    claim: c
    sources:
      - kind: external
        source_id: s1
    threshold:
      unanimous: false`,
			contain: "threshold.unanimous must be true",
		},
		{
			name: "majority must be true",
			rules: `  - id: r1
    type: consensus
    claim: c
    sources:
      - kind: external
        source_id: s1
    threshold:
      majority: 0`,
			contain: "threshold.majority must be true",
		},
		{
			name: "agree_at_least too small",
			rules: `  - id: r1
    type: consensus
    claim: c
    sources:
      - kind: external
        source_id: s1
    threshold:
      agree_at_least: 0`,
			contain: "agree_at_least must be >= 1",
		},
		{
			name: "agree_at_least non numeric",
			rules: `  - id: r1
    type: consensus
    claim: c
    sources:
      - kind: external
        source_id: s1
    threshold:
      agree_at_least: maybe`,
			contain: "agree_at_least must be numeric",
		},
		{
			name: "multiple threshold keys",
			rules: `  - id: r1
    type: consensus
    claim: c
    sources:
      - kind: external
        source_id: s1
    threshold:
      unanimous: true
      majority: true`,
			contain: "exactly one of unanimous",
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

func TestCompileCardinalityMinMaxValidation(t *testing.T) {
	_, err := Compile(wrap(`  - id: r1
    type: cardinality
    action: demo.action
    min: 2
    max: 1`))
	if err == nil || !strings.Contains(err.Error(), "min cannot be greater than max") {
		t.Fatalf("err=%v", err)
	}
}

func TestCompileConsensusThresholdAgreeAtLeastInt64(t *testing.T) {
	_, err := Compile(wrap(`  - id: r1
    type: consensus
    claim: c
    sources:
      - kind: external
        source_id: s1
    threshold:
      agree_at_least: 2`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
