package policy

import "testing"

func TestIntFromAnyAcceptsInt64(t *testing.T) {
	v, err := intFromAny(int64(3), "min")
	if err != nil || v == nil || *v != 3 {
		t.Fatalf("v=%v err=%v", v, err)
	}
}

func TestIntFromAnyRejectsFloatWithFraction(t *testing.T) {
	if _, err := intFromAny(float64(1.5), "min"); err == nil {
		t.Fatal("expected fractional error")
	}
}

func TestIntFromAnyRejectsStringValue(t *testing.T) {
	if _, err := intFromAny("two", "min"); err == nil {
		t.Fatal("expected type error")
	}
}

func TestDiffOneRuleDetectsSpecKeyAdded(t *testing.T) {
	left := CanonicalRule{ID: "r1", Category: "required", Spec: map[string]any{"action": "a", "min": 1}}
	right := CanonicalRule{ID: "r1", Category: "required", Spec: map[string]any{"action": "a", "min": 1, "max": 2}}
	rd := diffOneRule(left, right)
	if rd == nil {
		t.Fatal("expected diff")
	}
	foundAdd := false
	for _, c := range rd.SpecChanges {
		if c.Kind == ChangeKindAdded && c.Key == "max" {
			foundAdd = true
		}
	}
	if !foundAdd {
		t.Fatalf("changes=%+v", rd.SpecChanges)
	}
}
