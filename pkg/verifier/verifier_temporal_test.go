package verifier

import (
	"testing"
	"time"
)

func TestEvaluateTemporalMissingFromAction(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e2","action":"b","status":"ok","started_at":"2026-05-12T00:00:02Z","completed_at":"2026-05-12T00:00:03Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"temporal","severity":"medium",
  "spec":{"from":{"action":"a"},"to":{"action":"b"},"max":"PT5M"}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "inconclusive.temporal.missing_anchor" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestEvaluateTemporalNegativeInterval(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"a","status":"ok","started_at":"2026-05-12T00:00:10Z","completed_at":"2026-05-12T00:00:11Z"},
  {"event_id":"e2","action":"b","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"temporal","severity":"high",
  "spec":{"from":{"action":"a"},"to":{"action":"b"},"max":"PT5M"}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "fail.temporal.negative_interval" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestEvaluateTemporalGoDurationMax(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"a","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"},
  {"event_id":"e2","action":"b","status":"ok","started_at":"2026-05-12T00:00:02Z","completed_at":"2026-05-12T00:00:03Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"temporal","severity":"medium",
  "spec":{"from":{"action":"a"},"to":{"action":"b"},"max":"2s"}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "pass.temporal.within_window" {
		t.Fatalf("%+v", run.Findings)
	}
}

func TestParseISODurationComposite(t *testing.T) {
	d, err := parseISODuration("PT1H30M15S")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Hour + 30*time.Minute + 15*time.Second
	if d != want {
		t.Fatalf("got %v want %v", d, want)
	}
}

func TestParseISODurationRejectsEmpty(t *testing.T) {
	if _, err := parseISODuration(""); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseISODurationRejectsBadUnit(t *testing.T) {
	if _, err := parseISODuration("PT1X"); err == nil {
		t.Fatal("expected error")
	}
}
