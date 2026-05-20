package verifier

import (
	"strings"
	"testing"
)

func TestTemporalNegativeInterval(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"a","status":"ok","started_at":"2026-05-12T00:00:10Z","completed_at":"2026-05-12T00:00:11Z"},
  {"event_id":"e2","action":"b","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"t1","category":"temporal","severity":"medium",
  "spec":{"from":{"action":"a"},"to":{"action":"b"},"max":"PT5M"}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "t1") != "fail.temporal.negative_interval" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestTemporalInvalidMaxDuration(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"a","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"},
  {"event_id":"e2","action":"b","status":"ok","started_at":"2026-05-12T00:00:02Z","completed_at":"2026-05-12T00:00:03Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"t1","category":"temporal","severity":"medium",
  "spec":{"from":{"action":"a"},"to":{"action":"b"},"max":"not-a-duration"}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "t1") != "inconclusive.temporal.duration_invalid" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestConsensusNoMatchingAttestations(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"c1","category":"consensus","severity":"medium",
  "spec":{"claim":"refund.ok","sources":[{"source_id":"s1"}],"threshold":{"unanimous":true}}
}]}`)
	atts := []byte(`{"attestation_id":"a1","claim":"other","claim_value":true,"source_id":"s1"}` + "\n")
	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "c1") != "fail.consensus.insufficient" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestConsensusGroupsWithoutExpectedValue(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"c1","category":"consensus","severity":"medium",
  "spec":{"claim":"refund.ok","sources":[{"source_id":"s1"}],"threshold":{"agree_at_least":1}}
}]}`)
	atts := []byte(
		`{"attestation_id":"a1","claim":"refund.ok","claim_value":true,"source_id":"s1"}` + "\n" +
			`{"attestation_id":"a2","claim":"refund.ok","claim_value":true,"source_id":"s1"}` + "\n",
	)
	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(reason(run, "c1"), "pass.consensus") {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestConsensusWithExpectedValueMatch(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"c1","category":"consensus","severity":"medium",
  "spec":{"claim":"refund.ok","expected_value":true,"sources":[{"source_id":"s1"}],"threshold":{"agree_at_least":1}}
}]}`)
	atts := []byte(`{"attestation_id":"a1","claim":"refund.ok","claim_value":true,"source_id":"s1"}` + "\n")
	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(reason(run, "c1"), "pass.consensus") {
		t.Fatalf("%+v", run.Findings)
	}
}
