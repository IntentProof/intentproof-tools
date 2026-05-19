package verifier

import "testing"

func TestEvaluateCardinalityUnderMin(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"tick","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"cardinality","severity":"medium","spec":{"action":"tick","min":2}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "fail.cardinality.under_min" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestEvaluateCardinalityOverMax(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"tick","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"},
  {"event_id":"e2","action":"tick","status":"ok","started_at":"2026-05-12T00:00:02Z","completed_at":"2026-05-12T00:00:03Z"},
  {"event_id":"e3","action":"tick","status":"ok","started_at":"2026-05-12T00:00:04Z","completed_at":"2026-05-12T00:00:05Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"cardinality","severity":"medium","spec":{"action":"tick","max":2}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "fail.cardinality.over_max" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestEvaluateForbiddenAfterPredecessorPassWhenAbsent(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"pay.refund","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"forbidden","severity":"medium",
  "spec":{"action":"pay.refund","after":"pay.setup"}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "pass.forbidden.absent" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestFilterAttestationsBySourceID(t *testing.T) {
	atts := []attestation{
		{AttestationID: "a1", SourceID: "src-a", Claim: "c", ClaimValue: 1},
		{AttestationID: "a2", SourceID: "src-b", Claim: "c", ClaimValue: 2},
	}
	matched := filterAttestations(atts, "c", "src-a")
	if len(matched) != 1 || matched[0].AttestationID != "a1" {
		t.Fatalf("got %+v", matched)
	}
}
