package verifier

import "testing"

func TestVerifyConsensusUnanimousPassWithExpectedValue(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"c1","category":"consensus","severity":"high",
  "spec":{"claim":"risk","expected_value":"low",
    "sources":[{"source_id":"s1"},{"source_id":"s2"}],
    "threshold":{"unanimous":true}}
}]}`)
	atts := []byte(`{"attestation_id":"a1","source_id":"s1","claim":"risk","claim_value":"low"}
{"attestation_id":"a2","source_id":"s2","claim":"risk","claim_value":"low"}
`)
	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "c1") != "pass.consensus.threshold_met" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestVerifyOrderingBeforeActionMissing(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"finish","status":"ok","started_at":"2026-05-12T00:00:01Z","completed_at":"2026-05-12T00:00:02Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"o1","category":"ordering","severity":"medium",
  "spec":{"before":"start","after":"finish"}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "o1") != "inconclusive.ordering.before_missing" {
		t.Fatalf("%+v", run.Findings)
	}
}
