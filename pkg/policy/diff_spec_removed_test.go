package policy

import "testing"

func TestDiffOneRuleDetectsSpecKeyRemoved(t *testing.T) {
	left := CanonicalRule{ID: "r1", Category: "required", Spec: map[string]any{"action": "a", "min": 1, "max": 2}}
	right := CanonicalRule{ID: "r1", Category: "required", Spec: map[string]any{"action": "a", "min": 1}}
	rd := diffOneRule(left, right)
	if rd == nil {
		t.Fatal("expected diff")
	}
	foundRemove := false
	for _, c := range rd.SpecChanges {
		if c.Kind == ChangeKindRemoved && c.Key == "max" {
			foundRemove = true
		}
	}
	if !foundRemove {
		t.Fatalf("changes=%+v", rd.SpecChanges)
	}
}

func TestIntFromAnyAcceptsFloatWholeNumber(t *testing.T) {
	v, err := intFromAny(float64(4), "min")
	if err != nil || v == nil || *v != 4 {
		t.Fatalf("v=%v err=%v", v, err)
	}
}
