package verifier

import "testing"

func TestEvaluateForbiddenAfterPredecessorPassWhenBeforePred(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"pay.setup","status":"ok","started_at":"2026-05-12T00:00:10Z","completed_at":"2026-05-12T00:00:11Z"},
  {"event_id":"e2","action":"pay.refund","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"forbidden","severity":"high",
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

func TestEvaluateForbiddenWithoutPredecessorPassWithEarlierPred(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"pay.setup","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"},
  {"event_id":"e2","action":"pay.refund","status":"ok","started_at":"2026-05-12T00:00:10Z","completed_at":"2026-05-12T00:00:11Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"forbidden","severity":"high",
  "spec":{"action":"pay.refund","without_predecessor":"pay.setup"}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "pass.forbidden.absent" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestEvaluateForbiddenPresentReason(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"blocked","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"forbidden","severity":"critical","spec":{"action":"blocked"}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "fail.forbidden.present" {
		t.Fatalf("%+v", run.Findings)
	}
}
