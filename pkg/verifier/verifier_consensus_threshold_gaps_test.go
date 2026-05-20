package verifier

import (
	"strings"
	"testing"
)

func TestVerifyConsensusEmptyThresholdMap(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"c1","category":"consensus","severity":"high",
  "spec":{"claim":"risk","sources":[{"source_id":"s1"}],"threshold":{}}
}]}`)
	atts := []byte(`{"attestation_id":"a1","source_id":"s1","claim":"risk","claim_value":"low"}` + "\n")
	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "c1") != "fail.consensus.threshold_unmet" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestVerifyConsensusMultipleThresholdOperators(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"c1","category":"consensus","severity":"high",
  "spec":{"claim":"risk","sources":[{"source_id":"s1"}],
    "threshold":{"unanimous":true,"majority":true}}
}]}`)
	atts := []byte(`{"attestation_id":"a1","source_id":"s1","claim":"risk","claim_value":"low"}` + "\n")
	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reason(run, "c1"), "fail.consensus") {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestVerifyConsensusMajorityThreeWaySplit(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"c1","category":"consensus","severity":"high",
  "spec":{"claim":"risk","sources":[{"source_id":"s1"},{"source_id":"s2"},{"source_id":"s3"}],
    "threshold":{"majority":true}}
}]}`)
	atts := []byte(`{"attestation_id":"a1","source_id":"s1","claim":"risk","claim_value":"low"}
{"attestation_id":"a2","source_id":"s2","claim":"risk","claim_value":"medium"}
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

func TestVerifyConsensusMissingClaimField(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"c1","category":"consensus","severity":"high",
  "spec":{"sources":[{"source_id":"s1"}],"threshold":{"unanimous":true}}
}]}`)
	atts := []byte(`{"attestation_id":"a1","source_id":"s1","claim":"risk","claim_value":"low"}` + "\n")
	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "c1") != "inconclusive.consensus.claim_missing" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestParseAttestationsSkipsBlankLines(t *testing.T) {
	raw := []byte(`{"attestation_id":"a1","source_id":"s1","claim":"c","claim_value":1}

{"attestation_id":"a2","source_id":"s2","claim":"c","claim_value":1}
`)
	atts, err := parseAttestations(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(atts) != 2 {
		t.Fatalf("len=%d", len(atts))
	}
}

func TestVerifyBadAttestationsJSONL(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]}`)
	_, err := Verify(flow, policy, []byte("{not json}\n"))
	if err == nil || !strings.Contains(err.Error(), "parse attestations") {
		t.Fatalf("err=%v", err)
	}
}
