package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/policy"
)

func TestAssignEvidenceActionsRequired(t *testing.T) {
	out := map[string]string{}
	rule := policy.CanonicalRule{
		Category: "required",
		Spec:     map[string]any{"action": "pay.execute"},
	}
	assignEvidenceActions(rule, []string{"evt_1"}, out)
	if out["evt_1"] != "pay.execute" {
		t.Fatalf("out=%v", out)
	}
}

func TestAssignEvidenceActionsOrdering(t *testing.T) {
	out := map[string]string{}
	rule := policy.CanonicalRule{
		Category: "ordering",
		Spec: map[string]any{
			"before": "pay.setup",
			"after":  "pay.capture",
		},
	}
	assignEvidenceActions(rule, []string{"evt_a", "evt_b"}, out)
	if out["evt_a"] != "pay.setup" || out["evt_b"] != "pay.capture" {
		t.Fatalf("out=%v", out)
	}
}

func TestAssignEvidenceActionsTemporal(t *testing.T) {
	out := map[string]string{}
	rule := policy.CanonicalRule{
		Category: "temporal",
		Spec: map[string]any{
			"from": map[string]any{"action": "pay.start"},
			"to":   map[string]any{"action": "pay.end"},
		},
	}
	assignEvidenceActions(rule, []string{"evt_from", "evt_to"}, out)
	if out["evt_from"] != "pay.start" || out["evt_to"] != "pay.end" {
		t.Fatalf("out=%v", out)
	}
}

func TestUpdateJSONFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "doc.json")
	if err := os.WriteFile(path, []byte(`{"a":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := updateJSONFile(path, func(doc map[string]any) {
		doc["b"] = 2
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(raw), `"b"`) {
		t.Fatalf("raw=%s", raw)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
