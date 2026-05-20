package policy

import "testing"

func TestDiffSortsPolicyAndSpecChanges(t *testing.T) {
	left := &CompileResult{Policy: CanonicalPolicy{
		PolicyID: "a.policy", TenantID: "tnt", PolicyVersion: 1,
		Name: "left", Description: "left-desc",
		Rules: []CanonicalRule{{
			ID: "r1", Category: "required", Severity: "low",
			Spec: map[string]any{"action": "a", "min": 1, "max": 2},
		}},
	}}
	right := &CompileResult{Policy: CanonicalPolicy{
		PolicyID: "b.policy", TenantID: "tnt", PolicyVersion: 2,
		Name: "right", Description: "right-desc",
		Rules: []CanonicalRule{{
			ID: "r1", Category: "required", Severity: "high",
			Spec: map[string]any{"action": "b", "min": 2, "max": 3, "where": map[string]any{"status": "ok"}},
		}},
	}}
	result := Diff(left, right)
	if result.Same {
		t.Fatal("expected differences")
	}
	if len(result.PolicyChanges) < 2 {
		t.Fatalf("policy changes=%+v", result.PolicyChanges)
	}
	if len(result.RuleChanges) != 1 || len(result.RuleChanges[0].SpecChanges) < 2 {
		t.Fatalf("rule changes=%+v", result.RuleChanges)
	}
}

func TestDeepJSONEqualFallbackOnNonJSONValues(t *testing.T) {
	if deepJSONEqual(map[string]any{"x": make(chan int)}, map[string]any{"x": make(chan int)}) {
		t.Fatal("expected channel maps to compare unequal")
	}
}
