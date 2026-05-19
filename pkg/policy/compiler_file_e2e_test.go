package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCompileFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	raw := []byte(`
policy_id: tnt.test.policy
tenant_id: tnt_test
policy_version: 1
spec_version: 1.0.0
scope:
  any_event_action_in: [demo.action]
rules:
  - id: consensus-agree
    type: consensus
    claim: flag.ok
    sources:
      - kind: external
        source_id: src-a
    threshold:
      agree_at_least: 2
  - id: cardinality-range
    type: cardinality
    action: demo.action
    min: 1
    max: 3
`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := CompileFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if result.Fingerprint == "" {
		t.Fatal("expected fingerprint")
	}
}

func TestCompileRejectsInvalidThresholdCombo(t *testing.T) {
	raw := []byte(`
policy_id: tnt.test
tenant_id: tnt
policy_version: 1
spec_version: 1.0.0
rules:
  - id: c1
    type: consensus
    claim: x
    threshold:
      unanimous: true
      majority: true
`)
	if _, err := Compile(raw); err == nil {
		t.Fatal("expected threshold error")
	}
}

func TestNumericFromAnyAndIntFromAny(t *testing.T) {
	if v, ok := numericFromAny(3); !ok || v != 3 {
		t.Fatalf("int: %v %v", v, ok)
	}
	if v, ok := numericFromAny(int64(4)); !ok || v != 4 {
		t.Fatalf("int64: %v %v", v, ok)
	}
	if _, ok := numericFromAny("x"); ok {
		t.Fatal("string should fail")
	}
	if p, err := intFromAny(float64(2), "min"); err != nil || p == nil || *p != 2 {
		t.Fatalf("float min: %v %v", p, err)
	}
}
