package verifier

import "testing"

func TestVerifyConsensusUnanimousFalseThresholdUnmet(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	atts := []byte(`{"attestation_id":"a1","claim":"x","claim_value":1}
{"attestation_id":"a2","claim":"x","claim_value":2}
`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"consensus","severity":"high",
  "spec":{"claim":"x","threshold":{"unanimous":false}}
}]}`)
	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "fail.consensus.threshold_unmet" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestVerifyConsensusUnknownThresholdKey(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	atts := []byte(`{"attestation_id":"a1","claim":"x","claim_value":1}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"consensus","severity":"high",
  "spec":{"claim":"x","threshold":{"quorum":3}}
}]}`)
	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "fail.consensus.insufficient" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestVerifyConsensusFiltersSources(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	atts := []byte(`{"attestation_id":"a1","claim":"risk","claim_value":1,"source_id":"keep"}
{"attestation_id":"a2","claim":"risk","claim_value":1,"source_id":"drop"}
`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"consensus","severity":"high",
  "spec":{"claim":"risk","sources":[{"source_id":"keep"}],"threshold":{"unanimous":true}}
}]}`)
	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "pass" {
		t.Fatalf("status=%s %+v", run.Status, run.Findings)
	}
}

func TestVerifyConsensusNoMatchingAttestations(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"consensus","severity":"high",
  "spec":{"claim":"missing","threshold":{"agree_at_least":1}}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "fail.consensus.insufficient" {
		t.Fatalf("%+v", run.Findings)
	}
}
