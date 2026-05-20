package verifier

import "testing"

func TestVerifyRequiredWhereEqualsIntAttribute(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"pay","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z",
   "attributes":{"tier":1}}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"required","severity":"medium",
  "spec":{"action":"pay","min":1,"where":{"attribute":"tier","equals":1}}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "pass.required.satisfied" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestVerifyRequiredWhereInMatchesMixedNumericTypes(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"pay","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z",
   "attributes":{"tier":2}}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"required","severity":"medium",
  "spec":{"action":"pay","min":1,"where":{"attribute":"tier","in":[1,2,3]}}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "pass.required.satisfied" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestVerifyConsensusAgreeAtLeastFailure(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"c1","category":"consensus","severity":"high",
  "spec":{"claim":"risk","expected_value":"low",
    "sources":[{"source_id":"s1"},{"source_id":"s2"},{"source_id":"s3"}],
    "threshold":{"agree_at_least":2}}
}]}`)
	atts := []byte(`{"attestation_id":"a1","source_id":"s1","claim":"risk","claim_value":"low"}
{"attestation_id":"a2","source_id":"s2","claim":"risk","claim_value":"high"}
{"attestation_id":"a3","source_id":"s3","claim":"risk","claim_value":"high"}
`)
	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "c1") != "fail.consensus.disagreement" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestParseISODurationUnsupportedUnit(t *testing.T) {
	if _, err := parseISODuration("PT5X"); err == nil {
		t.Fatal("expected unsupported unit error")
	}
}

func TestParseDurationValueInvalid(t *testing.T) {
	if _, err := parseDurationValue("not-a-number"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestCanonicalClaimValueKeyFallback(t *testing.T) {
	key := canonicalClaimValueKey(make(chan int))
	if key == "" {
		t.Fatal("expected fallback key")
	}
}
