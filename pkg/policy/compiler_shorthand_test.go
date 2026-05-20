package policy

import "testing"

func TestCompileAllRuleCategoriesFromShorthand(t *testing.T) {
	raw := []byte(`
policy_id: tnt_shorthand.all
tenant_id: tnt_shorthand
policy_version: 1
spec_version: 1.0.0
scope:
  any_event_action_in:
    - payments.refund.execute
    - ledger.entry.write
    - customer.notify
rules:
  - id: req
    type: required
    action: payments.refund.execute
    min: 1
    where: { status: ok }
  - id: forbid
    type: forbidden
    action: payments.fraud.execute
    after: payments.refund.execute
    where_predecessor: { status: ok }
  - id: card
    type: cardinality
    action: customer.notify
    exactly: 1
  - id: ord
    type: ordering
    before: payments.refund.execute
    after: ledger.entry.write
  - id: temp
    type: temporal
    from: { action: payments.refund.execute }
    to: { action: customer.notify }
    max: PT5M
    clock_skew_tolerance: PT1S
  - id: cons
    type: consensus
    claim: refund.ok
    expected_value: true
    require_signed_sources: true
    sources:
      - kind: internal
        action: payments.refund.execute
    threshold:
      agree_at_least: 1
  - id: vb
    type: value_bound
    claim: risk.score
    operator: lte
    value: 0.9
    source_id: model-a
  - id: cm
    type: claim_match
    claim: refund.ok
    expected_value: true
    require_signed: true
`)
	res, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Policy.Rules) != 8 {
		t.Fatalf("rules=%d", len(res.Policy.Rules))
	}
}

func TestCompileClaimMatchRequireSignedAlias(t *testing.T) {
	raw := wrap(`  - id: cm
    type: claim_match
    claim: c
    expected_value: true
    require_signed: true
`)
	if _, err := Compile(raw); err != nil {
		t.Fatal(err)
	}
}
