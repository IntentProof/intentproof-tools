package verifier

import (
	"strings"
	"testing"
	"time"
)

func TestVerifyEmptyFlowNoRules(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[]}`)

	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != "pass" {
		t.Fatalf("expected pass, got %s", run.Status)
	}
	if run.PolicyID != "p1" {
		t.Fatalf("expected policy_id p1, got %s", run.PolicyID)
	}
	if !strings.HasPrefix(run.RunFingerprint, "sha256:") {
		t.Fatalf("expected fingerprint prefix, got %s", run.RunFingerprint)
	}
}

func TestVerifyRequiredRulePass(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[{"event_id":"e1","action":"pay","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"}]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[{"id":"r1","category":"required","severity":"medium","spec":{"action":"pay","min":1}}]}`)

	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != "pass" {
		t.Fatalf("expected pass, got %s", run.Status)
	}
	if len(run.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(run.Findings))
	}
	if run.Findings[0]["outcome"] != "pass" {
		t.Fatalf("expected finding pass, got %v", run.Findings[0]["outcome"])
	}
}

func TestVerifyRequiredRuleFail(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[{"id":"r1","category":"required","severity":"high","spec":{"action":"pay","min":1}}]}`)

	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != "fail" {
		t.Fatalf("expected fail, got %s", run.Status)
	}
	if run.Findings[0]["outcome"] != "fail" {
		t.Fatalf("expected finding fail, got %v", run.Findings[0]["outcome"])
	}
}

func TestVerifyRequiredRuleWithWhere(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[
		{"event_id":"e1","action":"pay","status":"error","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"},
		{"event_id":"e2","action":"pay","status":"ok","started_at":"2026-05-12T00:00:02Z","completed_at":"2026-05-12T00:00:03Z"}
	]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[{"id":"r1","category":"required","severity":"medium","spec":{"action":"pay","min":1,"where":{"status":"ok"}}}]}`)

	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != "pass" {
		t.Fatalf("expected pass, got %s", run.Status)
	}
}

func TestVerifyForbiddenRulePass(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[{"event_id":"e1","action":"ok-action","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"}]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[{"id":"r1","category":"forbidden","severity":"critical","spec":{"action":"bad"}}]}`)

	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != "pass" {
		t.Fatalf("expected pass, got %s", run.Status)
	}
}

func TestVerifyForbiddenRuleFail(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[{"event_id":"e1","action":"bad","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"}]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[{"id":"r1","category":"forbidden","severity":"critical","spec":{"action":"bad"}}]}`)

	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != "fail" {
		t.Fatalf("expected fail, got %s", run.Status)
	}
}

func TestVerifyOrderingRulePass(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[
		{"event_id":"e1","action":"a","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"},
		{"event_id":"e2","action":"b","status":"ok","started_at":"2026-05-12T00:00:02Z","completed_at":"2026-05-12T00:00:03Z"}
	]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[{"id":"r1","category":"ordering","severity":"medium","spec":{"before":"a","after":"b"}}]}`)

	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != "pass" {
		t.Fatalf("expected pass, got %s", run.Status)
	}
}

func TestVerifyOrderingRuleFail(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[
		{"event_id":"e1","action":"b","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"},
		{"event_id":"e2","action":"a","status":"ok","started_at":"2026-05-12T00:00:02Z","completed_at":"2026-05-12T00:00:03Z"}
	]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[{"id":"r1","category":"ordering","severity":"medium","spec":{"before":"a","after":"b"}}]}`)

	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != "fail" {
		t.Fatalf("expected fail, got %s", run.Status)
	}
}

func TestVerifyCardinalityExactly(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[
		{"event_id":"e1","action":"pay","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"}
	]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[{"id":"r1","category":"cardinality","severity":"medium","spec":{"action":"pay","exactly":1}}]}`)

	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != "pass" {
		t.Fatalf("expected pass, got %s", run.Status)
	}
}

func TestVerifyCardinalityFail(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[
		{"event_id":"e1","action":"pay","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"},
		{"event_id":"e2","action":"pay","status":"ok","started_at":"2026-05-12T00:00:02Z","completed_at":"2026-05-12T00:00:03Z"}
	]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[{"id":"r1","category":"cardinality","severity":"medium","spec":{"action":"pay","exactly":1}}]}`)

	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != "fail" {
		t.Fatalf("expected fail, got %s", run.Status)
	}
}

func TestVerifyTemporalRulePass(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[
		{"event_id":"e1","action":"a","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"},
		{"event_id":"e2","action":"b","status":"ok","started_at":"2026-05-12T00:00:02Z","completed_at":"2026-05-12T00:00:03Z"}
	]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[{"id":"r1","category":"temporal","severity":"medium","spec":{"from":{"action":"a"},"to":{"action":"b"},"max":"PT10M"}}]}`)

	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != "pass" {
		t.Fatalf("expected pass, got %s", run.Status)
	}
}

func TestVerifyTemporalRuleFail(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[
		{"event_id":"e1","action":"a","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"},
		{"event_id":"e2","action":"b","status":"ok","started_at":"2026-05-12T00:01:00Z","completed_at":"2026-05-12T00:01:01Z"}
	]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[{"id":"r1","category":"temporal","severity":"medium","spec":{"from":{"action":"a"},"to":{"action":"b"},"max":"PT30S"}}]}`)

	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != "fail" {
		t.Fatalf("expected fail, got %s", run.Status)
	}
}

func TestVerifyConsensusUnanimousPass(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[{"id":"r1","category":"consensus","severity":"critical","spec":{"claim":"refund.ok","sources":[{"kind":"external","source_id":"stripe"}],"threshold":{"unanimous":true}}}]}`)
	atts := []byte(`{"schema":"intentproof.attestation.v1","attestation_id":"a1","tenant_id":"tnt","source_id":"stripe","received_at":"2026-05-12T00:00:00Z","source_emitted_at":"2026-05-12T00:00:00Z","subject":{"type":"refund","id":"r1","mapping_to":{"correlation_id":"c1"}},"claim":"refund.ok","claim_value":true,"source_payload_sha256":"sha256:0000","source_signature":{"alg":"ed25519","key_id":"k1","value":"sig"},"platform_signature":{"alg":"ed25519","key_id":"p1","value":"psig"}}`)

	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != "pass" {
		t.Fatalf("expected pass, got %s", run.Status)
	}
}

func TestVerifyConsensusDisagreement(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[{"id":"r1","category":"consensus","severity":"critical","spec":{"claim":"refund.ok","expected_value":true,"sources":[{"kind":"external","source_id":"stripe"}],"threshold":{"unanimous":true}}}]}`)
	atts := []byte(`{"schema":"intentproof.attestation.v1","attestation_id":"a1","tenant_id":"tnt","source_id":"stripe","received_at":"2026-05-12T00:00:00Z","source_emitted_at":"2026-05-12T00:00:00Z","subject":{"type":"refund","id":"r1","mapping_to":{"correlation_id":"c1"}},"claim":"refund.ok","claim_value":false,"source_payload_sha256":"sha256:0000","source_signature":{"alg":"ed25519","key_id":"k1","value":"sig"},"platform_signature":{"alg":"ed25519","key_id":"p1","value":"psig"}}`)

	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != "fail" {
		t.Fatalf("expected fail, got %s", run.Status)
	}
	reason := run.Findings[0]["reason"].(string)
	if !strings.Contains(reason, "consensus.disagreement") {
		t.Fatalf("expected consensus.disagreement reason, got %s", reason)
	}
}

func TestVerifyDeterministicFingerprint(t *testing.T) {
	origNow := nowFunc
	fixed := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	nowFunc = func() time.Time { return fixed }
	defer func() { nowFunc = origNow }()

	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[{"event_id":"e1","action":"pay","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"}]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[{"id":"r1","category":"required","severity":"medium","spec":{"action":"pay","min":1}}]}`)

	run1, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	run2, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run1.RunFingerprint != run2.RunFingerprint {
		t.Fatalf("fingerprint not deterministic: %s vs %s", run1.RunFingerprint, run2.RunFingerprint)
	}
}

func TestVerifyMultipleRulesMixedOutcomes(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[
		{"event_id":"e1","action":"pay","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"}
	]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[
		{"id":"r1","category":"required","severity":"medium","spec":{"action":"pay","min":1}},
		{"id":"r2","category":"forbidden","severity":"high","spec":{"action":"bad"}}
	]}`)

	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != "pass" {
		t.Fatalf("expected pass, got %s", run.Status)
	}
	if len(run.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(run.Findings))
	}
	if run.Summary.OutcomeCounts["pass"] != 2 {
		t.Fatalf("expected 2 passes, got %v", run.Summary.OutcomeCounts)
	}
	if run.Summary.SeverityCounts["medium"] != 1 || run.Summary.SeverityCounts["high"] != 1 {
		t.Fatalf("unexpected severity counts: %v", run.Summary.SeverityCounts)
	}
}

func TestVerifySummaryCountsOnFail(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[
		{"id":"r1","category":"required","severity":"critical","spec":{"action":"pay","min":1}},
		{"id":"r2","category":"forbidden","severity":"info","spec":{"action":"bad"}}
	]}`)

	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != "fail" {
		t.Fatalf("expected fail, got %s", run.Status)
	}
	if run.Summary.OutcomeCounts["fail"] != 1 || run.Summary.OutcomeCounts["pass"] != 1 {
		t.Fatalf("unexpected outcome counts: %v", run.Summary.OutcomeCounts)
	}
	if run.Summary.SeverityCounts["critical"] != 1 || run.Summary.SeverityCounts["info"] != 1 {
		t.Fatalf("unexpected severity counts: %v", run.Summary.SeverityCounts)
	}
}

func TestVerifyAttestationSet(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[]}`)
	atts := []byte(
		`{"schema":"intentproof.attestation.v1","attestation_id":"a1","tenant_id":"tnt","source_id":"stripe","received_at":"2026-05-12T00:00:00Z","source_emitted_at":"2026-05-12T00:00:00Z","subject":{"type":"refund","id":"r1","mapping_to":{"correlation_id":"c1"}},"claim":"refund.ok","claim_value":true,"source_payload_sha256":"sha256:0000","source_signature":{"alg":"ed25519","key_id":"k1","value":"sig"},"platform_signature":{"alg":"ed25519","key_id":"p1","value":"psig"}}` + "\n" +
			`{"schema":"intentproof.attestation.v1","attestation_id":"a2","tenant_id":"tnt","source_id":"stripe","received_at":"2026-05-12T00:00:00Z","source_emitted_at":"2026-05-12T00:00:00Z","subject":{"type":"refund","id":"r1","mapping_to":{"correlation_id":"c1"}},"claim":"refund.ok","claim_value":true,"source_payload_sha256":"sha256:0000","source_signature":{"alg":"ed25519","key_id":"k1","value":"sig"},"platform_signature":{"alg":"ed25519","key_id":"p1","value":"psig"}}`)

	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(run.AttestationSet.IDs) != 2 {
		t.Fatalf("expected 2 attestation IDs, got %d", len(run.AttestationSet.IDs))
	}
	if run.AttestationSet.MerkleRoot == "" {
		t.Fatalf("expected non-empty merkle root")
	}
}

func TestVerifyRunStructure(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:abc","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[]}`)

	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Schema != "intentproof.run.v1" {
		t.Fatalf("unexpected schema: %s", run.Schema)
	}
	if run.FlowID != "f1" {
		t.Fatalf("unexpected flow_id: %s", run.FlowID)
	}
	if run.FlowMerkleRoot != "sha256:abc" {
		t.Fatalf("unexpected flow_merkle_root: %s", run.FlowMerkleRoot)
	}
	if run.VerifierVersion != verifierVersion {
		t.Fatalf("unexpected verifier_version: %s", run.VerifierVersion)
	}
	if run.Signature["alg"] != "ed25519" {
		t.Fatalf("unexpected signature alg: %v", run.Signature["alg"])
	}
}

func TestVerifyJSONParseErrors(t *testing.T) {
	_, err := Verify([]byte(`not json`), []byte(`{}`), nil)
	if err == nil {
		t.Fatal("expected error for invalid flow JSON")
	}
	if !strings.Contains(err.Error(), "parse flow") {
		t.Fatalf("expected parse flow error, got %v", err)
	}

	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:abc","events":[]}`)
	_, err = Verify(flow, []byte(`not json`), nil)
	if err == nil {
		t.Fatal("expected error for invalid policy JSON")
	}
	if !strings.Contains(err.Error(), "parse policy") {
		t.Fatalf("expected parse policy error, got %v", err)
	}
}

func TestVerifyFingerprintExcludesItselfAndSignature(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:abc","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[]}`)

	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// The run must retain its fingerprint and signature in the response.
	if run.RunFingerprint == "" {
		t.Fatal("run_fingerprint should be present on returned run")
	}
	if run.Signature == nil {
		t.Fatal("signature should be present on returned run")
	}

	// Compute fingerprint again from the returned run: it should be identical,
	// proving the fingerprint computation is internally consistent.
	fp2, err := computeRunFingerprint(run)
	if err != nil {
		t.Fatalf("computeRunFingerprint: %v", err)
	}
	if run.RunFingerprint != fp2 {
		t.Fatalf("fingerprint mismatch: %s vs %s", run.RunFingerprint, fp2)
	}
}
