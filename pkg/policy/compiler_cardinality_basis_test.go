package policy

import "testing"

func TestCompileCardinalityWithCountBasisAndWhere(t *testing.T) {
	raw := []byte(`
policy_id: tnt_card.demo
tenant_id: tnt_card
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: cardinality
    action: demo.action
    min: 1
    max: 3
    count_basis: events
    where:
      status: ok
`)
	res, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	spec := res.Policy.Rules[0].Spec
	if spec["count_basis"] != "events" {
		t.Fatalf("spec=%v", spec)
	}
	if spec["where"] == nil {
		t.Fatal("expected where clause")
	}
}

func TestCompileForbiddenWithWithoutPredecessor(t *testing.T) {
	raw := []byte(`
policy_id: tnt_forb.demo
tenant_id: tnt_forb
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: forbidden
    action: bad.action
    after: ok.action
    without_predecessor: ok.action
`)
	res, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Policy.Rules[0].Spec["without_predecessor"] != "ok.action" {
		t.Fatalf("spec=%v", res.Policy.Rules[0].Spec)
	}
}
