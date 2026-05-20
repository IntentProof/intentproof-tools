package verifier

import "testing"

func TestVerifyOrderingBeforeMissing(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e2","action":"b","status":"ok","started_at":"2026-05-12T00:00:02Z","completed_at":"2026-05-12T00:00:03Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"ordering","severity":"medium","spec":{"before":"a","after":"b"}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "inconclusive.ordering.before_missing" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestVerifyOrderingAfterMissing(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"a","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"ordering","severity":"medium","spec":{"before":"a","after":"b"}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "inconclusive.ordering.after_missing" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestVerifyConsensusUnanimousWithoutSourcesList(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	atts := []byte(`{"attestation_id":"a1","claim":"ok","claim_value":true}
{"attestation_id":"a2","claim":"ok","claim_value":true}
`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"consensus","severity":"high",
  "spec":{"claim":"ok","threshold":{"unanimous":true}}
}]}`)
	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "pass" {
		t.Fatalf("status=%s %+v", run.Status, run.Findings)
	}
}

func TestVerifyConsensusWithSourceActionFilter(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	atts := []byte(`{"attestation_id":"a1","claim":"risk","claim_value":1,"source_id":"model-a"}
`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"consensus","severity":"high",
  "spec":{"claim":"risk","sources":[{"action":"model-a"}],"threshold":{"agree_at_least":1}}
}]}`)
	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "pass" {
		t.Fatalf("status=%s", run.Status)
	}
}
