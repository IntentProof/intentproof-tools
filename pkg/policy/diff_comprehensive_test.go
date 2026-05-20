package policy

import "testing"

func TestDiffRuleSpecChanges(t *testing.T) {
	left, _ := Compile(wrap(`  - id: r1
    type: required
    action: demo.action
    min: 1
    max: 5
`))
	right, _ := Compile(wrap(`  - id: r1
    type: required
    action: demo.other
    min: 2
`))
	res := Diff(left, right)
	if res.Same {
		t.Fatal("expected diff")
	}
	out := FormatDiff(res)
	if out == "" {
		t.Fatal("empty format")
	}
}

func TestDiffDetectsRemovedRule(t *testing.T) {
	left, _ := Compile(wrap(`  - id: r1
    type: required
    action: demo.action
    min: 1
  - id: r2
    type: forbidden
    action: demo.block
`))
	right, _ := Compile(wrap(`  - id: r1
    type: required
    action: demo.action
    min: 1
`))
	res := Diff(left, right)
	if len(res.RuleChanges) == 0 {
		t.Fatal("expected rule removal")
	}
}
