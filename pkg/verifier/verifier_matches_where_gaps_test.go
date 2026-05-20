package verifier

import "testing"

func TestVerifyRequiredWhereAttributeMissing(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"pay","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"required","severity":"medium",
  "spec":{"action":"pay","min":1,"where":{"attribute":"env","equals":"prod"}}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "fail.required.missing" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestVerifyRequiredWhereInNoMatch(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"pay","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z",
   "attributes":{"env":"staging"}}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"required","severity":"medium",
  "spec":{"action":"pay","min":1,"where":{"attribute":"env","in":["prod","live"]}}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "fail.required.missing" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestVerifyTemporalMissingToAction(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"start","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"t1","category":"temporal","severity":"medium",
  "spec":{"from":{"action":"start"},"to":{"action":"finish"},"max":"PT1H"}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "t1") != "inconclusive.temporal.missing_anchor" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestVerifyForbiddenWithoutPredecessorAfterForbidden(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"forbidden.action","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"},
  {"event_id":"e2","action":"before.action","status":"ok","started_at":"2026-05-12T00:00:02Z","completed_at":"2026-05-12T00:00:03Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"f1","category":"forbidden","severity":"high",
  "spec":{"action":"forbidden.action","without_predecessor":"before.action"}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "f1") != "fail.forbidden.without_predecessor" {
		t.Fatalf("%+v", run.Findings)
	}
}
