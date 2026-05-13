package policy

import (
	"strings"
	"testing"
)

func mustCompile(t *testing.T, raw []byte) *CompileResult {
	t.Helper()
	res, err := Compile(raw)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	return res
}

func TestDiffIdenticalPolicies(t *testing.T) {
	yaml := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
`
	left := mustCompile(t, []byte(yaml))
	right := mustCompile(t, []byte(yaml))

	diff := Diff(left, right)
	if !diff.Same {
		t.Fatalf("expected identical policies to produce Same=true")
	}
	if len(diff.PolicyChanges) != 0 {
		t.Fatalf("expected no policy changes, got %+v", diff.PolicyChanges)
	}
	if len(diff.RuleChanges) != 0 {
		t.Fatalf("expected no rule changes, got %+v", diff.RuleChanges)
	}
	if diff.OldFingerprint != diff.NewFingerprint {
		t.Fatalf("expected identical fingerprints")
	}
}

func TestDiffAddedRule(t *testing.T) {
	leftYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
`
	rightYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
  - id: r2
    type: forbidden
    action: payments.stripe.refunds.void
`
	left := mustCompile(t, []byte(leftYAML))
	right := mustCompile(t, []byte(rightYAML))

	diff := Diff(left, right)
	if diff.Same {
		t.Fatalf("expected diff.Same=false")
	}
	if len(diff.RuleChanges) != 1 {
		t.Fatalf("expected 1 rule change, got %d", len(diff.RuleChanges))
	}
	if diff.RuleChanges[0].Kind != ChangeKindAdded {
		t.Fatalf("expected added rule, got %s", diff.RuleChanges[0].Kind)
	}
	if diff.RuleChanges[0].RuleID != "r2" {
		t.Fatalf("expected r2 added, got %s", diff.RuleChanges[0].RuleID)
	}
}

func TestDiffRemovedRule(t *testing.T) {
	leftYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
  - id: r2
    type: forbidden
    action: payments.stripe.refunds.void
`
	rightYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
`
	left := mustCompile(t, []byte(leftYAML))
	right := mustCompile(t, []byte(rightYAML))

	diff := Diff(left, right)
	if diff.Same {
		t.Fatalf("expected diff.Same=false")
	}
	if len(diff.RuleChanges) != 1 {
		t.Fatalf("expected 1 rule change, got %d", len(diff.RuleChanges))
	}
	if diff.RuleChanges[0].Kind != ChangeKindRemoved {
		t.Fatalf("expected removed rule, got %s", diff.RuleChanges[0].Kind)
	}
	if diff.RuleChanges[0].RuleID != "r2" {
		t.Fatalf("expected r2 removed, got %s", diff.RuleChanges[0].RuleID)
	}
}

func TestDiffChangedRuleSpec(t *testing.T) {
	leftYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
`
	rightYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 2
`
	left := mustCompile(t, []byte(leftYAML))
	right := mustCompile(t, []byte(rightYAML))

	diff := Diff(left, right)
	if diff.Same {
		t.Fatalf("expected diff.Same=false")
	}
	if len(diff.RuleChanges) != 1 {
		t.Fatalf("expected 1 rule change, got %d", len(diff.RuleChanges))
	}
	if diff.RuleChanges[0].Kind != ChangeKindChanged {
		t.Fatalf("expected changed rule, got %s", diff.RuleChanges[0].Kind)
	}
	if len(diff.RuleChanges[0].SpecChanges) != 1 {
		t.Fatalf("expected 1 spec change, got %d", len(diff.RuleChanges[0].SpecChanges))
	}
	sc := diff.RuleChanges[0].SpecChanges[0]
	if sc.Key != "min" {
		t.Fatalf("expected min spec change, got %s", sc.Key)
	}
	if sc.Kind != ChangeKindChanged {
		t.Fatalf("expected changed spec, got %s", sc.Kind)
	}
}

func TestDiffMetadataChange(t *testing.T) {
	leftYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
`
	rightYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 2
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
`
	left := mustCompile(t, []byte(leftYAML))
	right := mustCompile(t, []byte(rightYAML))

	diff := Diff(left, right)
	if diff.Same {
		t.Fatalf("expected diff.Same=false")
	}
	if len(diff.PolicyChanges) != 1 {
		t.Fatalf("expected 1 policy change, got %d", len(diff.PolicyChanges))
	}
	if diff.PolicyChanges[0].Field != "policy_version" {
		t.Fatalf("expected policy_version change, got %s", diff.PolicyChanges[0].Field)
	}
}

func TestDiffScopeChange(t *testing.T) {
	leftYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
`
	rightYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.void
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
`
	left := mustCompile(t, []byte(leftYAML))
	right := mustCompile(t, []byte(rightYAML))

	diff := Diff(left, right)
	found := false
	for _, c := range diff.PolicyChanges {
		if c.Field == "scope" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected scope change in policy changes, got %+v", diff.PolicyChanges)
	}
}

func TestDiffDeterministicOrder(t *testing.T) {
	leftYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: a
rules:
  - id: z
    type: required
    action: a
    min: 1
  - id: a
    type: forbidden
    action: b
`
	rightYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: a
rules:
  - id: z
    type: required
    action: a
    min: 2
  - id: a
    type: forbidden
    action: c
`
	left := mustCompile(t, []byte(leftYAML))
	right := mustCompile(t, []byte(rightYAML))

	d1 := Diff(left, right)
	d2 := Diff(left, right)

	f1 := FormatDiff(d1)
	f2 := FormatDiff(d2)
	if f1 != f2 {
		t.Fatalf("diff format not deterministic:\n%s\nvs\n%s", f1, f2)
	}

	// Rule changes should be ordered by rule ID.
	ids := make([]string, len(d1.RuleChanges))
	for i, rc := range d1.RuleChanges {
		ids[i] = rc.RuleID
	}
	if ids[0] != "a" || ids[1] != "z" {
		t.Fatalf("expected rule order [a, z], got %v", ids)
	}
}

func TestFormatDiffIdentical(t *testing.T) {
	leftYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
`
	left := mustCompile(t, []byte(leftYAML))
	diff := Diff(left, left)
	out := FormatDiff(diff)
	if !strings.Contains(out, "semantically identical") {
		t.Fatalf("expected identical message, got: %s", out)
	}
}

func TestFormatDiffHumanReadable(t *testing.T) {
	leftYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
`
	rightYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 2
  - id: r2
    type: forbidden
    action: payments.stripe.refunds.void
`
	left := mustCompile(t, []byte(leftYAML))
	right := mustCompile(t, []byte(rightYAML))

	diff := Diff(left, right)
	out := FormatDiff(diff)

	if !strings.Contains(out, "+ r2") {
		t.Fatalf("expected added r2 in output, got: %s", out)
	}
	if !strings.Contains(out, "~ r1") {
		t.Fatalf("expected changed r1 in output, got: %s", out)
	}
	if !strings.Contains(out, "~ min:") {
		t.Fatalf("expected min change in output, got: %s", out)
	}
	if !strings.Contains(out, "old fingerprint:") {
		t.Fatalf("expected old fingerprint in output, got: %s", out)
	}
	if !strings.Contains(out, "new fingerprint:") {
		t.Fatalf("expected new fingerprint in output, got: %s", out)
	}
}

func TestDiffCategoryChange(t *testing.T) {
	leftYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
`
	rightYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: forbidden
    action: payments.stripe.refunds.create
`
	left := mustCompile(t, []byte(leftYAML))
	right := mustCompile(t, []byte(rightYAML))

	diff := Diff(left, right)
	if len(diff.RuleChanges) != 1 {
		t.Fatalf("expected 1 rule change, got %d", len(diff.RuleChanges))
	}
	sc := diff.RuleChanges[0].SpecChanges
	found := false
	for _, c := range sc {
		if c.Key == "category" {
			found = true
			if c.OldValue != "required" || c.NewValue != "forbidden" {
				t.Fatalf("unexpected category values: %+v", c)
			}
		}
	}
	if !found {
		t.Fatalf("expected category spec change, got %+v", sc)
	}
}

func TestDiffSeverityChange(t *testing.T) {
	leftYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    severity: low
    action: payments.stripe.refunds.create
    min: 1
`
	rightYAML := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    severity: high
    action: payments.stripe.refunds.create
    min: 1
`
	left := mustCompile(t, []byte(leftYAML))
	right := mustCompile(t, []byte(rightYAML))

	diff := Diff(left, right)
	found := false
	for _, c := range diff.RuleChanges[0].SpecChanges {
		if c.Key == "severity" {
			found = true
			if c.OldValue != "low" || c.NewValue != "high" {
				t.Fatalf("unexpected severity values: %+v", c)
			}
		}
	}
	if !found {
		t.Fatalf("expected severity spec change")
	}
}
