package policy

import "testing"

func TestDiffNilPolicies(t *testing.T) {
	res := Diff(nil, nil)
	if !res.Same {
		t.Fatal("expected same")
	}
}

func TestDiffDetectsRuleAdded(t *testing.T) {
	left, err := Compile(wrap(`  - id: r1
    type: required
    action: demo.action
    min: 1
`))
	if err != nil {
		t.Fatal(err)
	}
	right, err := Compile(wrap(`  - id: r1
    type: required
    action: demo.action
    min: 1
  - id: r2
    type: forbidden
    action: demo.blocked
`))
	if err != nil {
		t.Fatal(err)
	}
	res := Diff(left, right)
	if res.Same {
		t.Fatal("expected diff")
	}
	if len(res.RuleChanges) == 0 {
		t.Fatal("expected rule changes")
	}
}

func TestFormatDiffNonEmpty(t *testing.T) {
	left, _ := Compile(wrap(`  - id: r1
    type: required
    action: demo.action
    min: 1
`))
	right, _ := Compile(wrap(`  - id: r1
    type: required
    action: demo.action
    min: 2
`))
	out := FormatDiff(Diff(left, right))
	if out == "" {
		t.Fatal("expected formatted diff")
	}
}
