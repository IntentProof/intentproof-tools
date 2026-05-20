package policy

import (
	"strings"
	"testing"
)

func TestFormatDiffRuleAddedAndRemoved(t *testing.T) {
	left, err := Compile(wrap(`  - id: r1
    type: required
    action: demo.action
    min: 1`))
	if err != nil {
		t.Fatal(err)
	}
	right, err := Compile(wrap(`  - id: r2
    type: required
    action: demo.action2
    min: 1`))
	if err != nil {
		t.Fatal(err)
	}
	out := FormatDiff(Diff(left, right))
	if !strings.Contains(out, "+ r2") || !strings.Contains(out, "- r1") {
		t.Fatalf("output=%s", out)
	}
}

func TestFormatDiffPolicyMetadataChanged(t *testing.T) {
	left, err := Compile([]byte(`
policy_id: tnt_acme.test
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 1`))
	if err != nil {
		t.Fatal(err)
	}
	right, err := Compile([]byte(`
policy_id: tnt_acme.test
tenant_id: tnt_acme
policy_version: 2
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 1`))
	if err != nil {
		t.Fatal(err)
	}
	out := FormatDiff(Diff(left, right))
	if !strings.Contains(out, "policy_version") {
		t.Fatalf("output=%s", out)
	}
}
