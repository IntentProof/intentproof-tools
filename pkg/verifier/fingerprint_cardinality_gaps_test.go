package verifier

import (
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/policysig"
)

func TestValidateDeclaredPolicyFingerprintMatch(t *testing.T) {
	policy := map[string]any{
		"policy_id": "p1", "tenant_id": "tnt", "policy_version": 1,
		"rules": []any{},
	}
	fp, err := policysig.ComputeFingerprint(policy)
	if err != nil {
		t.Fatal(err)
	}
	policy["policy_fingerprint"] = fp
	if err := validateDeclaredPolicyFingerprint(policy); err != nil {
		t.Fatal(err)
	}
}

func TestValidateDeclaredPolicyFingerprintMismatch(t *testing.T) {
	policy := map[string]any{
		"policy_id": "p1", "tenant_id": "tnt", "policy_version": 1,
		"policy_fingerprint": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"rules": []any{},
	}
	if err := validateDeclaredPolicyFingerprint(policy); err == nil {
		t.Fatal("expected mismatch error")
	}
}

func TestValidateDeclaredPolicyFingerprintSkipsEmpty(t *testing.T) {
	if err := validateDeclaredPolicyFingerprint(map[string]any{"rules": []any{}}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyCardinalityExactlyPass(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"pay","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"},
  {"event_id":"e2","action":"pay","status":"ok","started_at":"2026-05-12T00:00:02Z","completed_at":"2026-05-12T00:00:03Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"c1","category":"cardinality","severity":"medium",
  "spec":{"action":"pay","exactly":2}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "c1") != "pass.cardinality.satisfied" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestComputeRunFingerprintRoundTrip(t *testing.T) {
	run := &VerificationRun{
		Schema: "intentproof.verification_run.v1",
		RunID:  "run_1",
		Status: "pass",
	}
	fp, err := computeRunFingerprint(run)
	if err != nil || fp == "" {
		t.Fatalf("fp=%q err=%v", fp, err)
	}
}
