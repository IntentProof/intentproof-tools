package policy

import (
	"strings"
	"testing"
)

func TestFormatDiffMetadataAndRuleChanges(t *testing.T) {
	left, err := Compile(wrap(`  - id: r1
    type: required
    action: demo.action
    min: 1`))
	if err != nil {
		t.Fatal(err)
	}
	right, err := Compile(wrap(`  - id: r1
    type: required
    action: demo.action
    min: 2`))
	if err != nil {
		t.Fatal(err)
	}
	result := Diff(left, right)
	out := FormatDiff(result)
	if strings.Contains(out, "semantically identical") {
		t.Fatalf("unexpected identical: %s", out)
	}
	if !strings.Contains(out, "rule changes:") || !strings.Contains(out, "~ r1") {
		t.Fatalf("output=%s", out)
	}
}

func TestDeepJSONEqualMarshalFallback(t *testing.T) {
	a := make(chan int)
	b := make(chan int)
	if deepJSONEqual(a, b) {
		t.Fatal("distinct channels should not compare equal")
	}
}
