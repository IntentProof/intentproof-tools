package policy

import (
	"strings"
	"testing"
)

func TestCompileValidPolicy(t *testing.T) {
	raw := []byte(`
policy_id: tnt_acme.refund-flow
policy_version: 4
tenant_id: tnt_acme
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: required-execute
    type: required
    action: payments.stripe.refunds.create
    min: 1
    where: { status: ok }
  - id: forbid-double-refund
    type: forbidden
    severity: critical
    action: payments.stripe.refunds.create
    after: payments.stripe.refunds.create
    where_predecessor: { status: ok }
  - id: ordering
    type: ordering
    before: payments.stripe.refunds.create
    after: customer.notify
  - id: temporal-execute-to-notify
    type: temporal
    from: { action: payments.stripe.refunds.create, anchor: completed_at }
    to: { action: customer.notify, anchor: started_at }
    max: PT5M
  - id: consensus-stripe-ack
    type: consensus
    claim: refund.acknowledged
    sources:
      - kind: internal
        action: payments.stripe.refunds.create
        where: { status: ok }
      - kind: external
        source_id: stripe@webhook
    threshold:
      unanimous: true
`)

	result, err := Compile(raw)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if result.Policy.Schema != "intentproof.policy.v1" {
		t.Fatalf("unexpected schema: %s", result.Policy.Schema)
	}
	if !strings.HasPrefix(result.Fingerprint, "sha256:") {
		t.Fatalf("unexpected fingerprint: %s", result.Fingerprint)
	}
	if result.Policy.PolicyFingerprint != result.Fingerprint {
		t.Fatalf("fingerprint mismatch")
	}
	if len(result.Policy.Scope.AnyEventActionIn) != 1 {
		t.Fatalf("unexpected scope actions: %+v", result.Policy.Scope.AnyEventActionIn)
	}
	consensus := result.Policy.Rules[4]
	sources := consensus.Spec["sources"].([]map[string]any)
	if sources[0]["kind"] != "intentproof_action" {
		t.Fatalf("expected internal source normalized, got: %v", sources[0]["kind"])
	}
}

func TestCompileRejectsCardinalityMutualExclusion(t *testing.T) {
	raw := []byte(`
policy_id: tnt_acme.bad
tenant_id: tnt_acme
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: c1
    type: cardinality
    action: demo.action
    exactly: 1
    min: 1
`)

	_, err := Compile(raw)
	if err == nil || !strings.Contains(err.Error(), "exactly conflicts") {
		t.Fatalf("expected mutual exclusion error, got: %v", err)
	}
}
