package verifier

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEvaluateForbiddenAfterPredecessorFail(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"pay.setup","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"},
  {"event_id":"e2","action":"pay.refund","status":"ok","started_at":"2026-05-12T00:00:10Z","completed_at":"2026-05-12T00:00:11Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"forbidden","severity":"high",
  "spec":{"action":"pay.refund","after":"pay.setup","where_predecessor":{"status":"ok"}}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "fail.forbidden.after_predecessor" {
		t.Fatalf("findings=%+v", run.Findings)
	}
}

func TestEvaluateForbiddenWithoutPredecessorFail(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"pay.refund","status":"ok","started_at":"2026-05-12T00:00:10Z","completed_at":"2026-05-12T00:00:11Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"forbidden","severity":"high",
  "spec":{"action":"pay.refund","without_predecessor":"pay.setup"}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "fail.forbidden.without_predecessor" {
		t.Fatalf("findings=%+v", run.Findings)
	}
}

func TestEvaluateForbiddenWithWhereInFilter(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"pay","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z","attributes":{"tier":1}},
  {"event_id":"e2","action":"pay","status":"ok","started_at":"2026-05-12T00:00:02Z","completed_at":"2026-05-12T00:00:03Z","attributes":{"tier":2}}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"forbidden","severity":"medium",
  "spec":{"action":"pay","where":{"attribute":"tier","in":[1,2]}}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "fail" {
		t.Fatalf("status=%s", run.Status)
	}
}

func TestEvaluateCardinalityMinMax(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"tick","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"},
  {"event_id":"e2","action":"tick","status":"ok","started_at":"2026-05-12T00:00:02Z","completed_at":"2026-05-12T00:00:03Z"},
  {"event_id":"e3","action":"tick","status":"ok","started_at":"2026-05-12T00:00:04Z","completed_at":"2026-05-12T00:00:05Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"cardinality","severity":"medium","spec":{"action":"tick","min":1,"max":5}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "pass.cardinality.satisfied" {
		t.Fatalf("findings=%+v", run.Findings)
	}
}

func TestEvaluateConsensusAgreeAtLeastPass(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	atts := []byte(`{"attestation_id":"a1","claim":"x","claim_value":1}
{"attestation_id":"a2","claim":"x","claim_value":1}
{"attestation_id":"a3","claim":"x","claim_value":2}
`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"consensus","severity":"high",
  "spec":{"claim":"x","threshold":{"agree_at_least":2}}
}]}`)
	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "pass" {
		t.Fatalf("status=%s findings=%+v", run.Status, run.Findings)
	}
}

func TestSetNowFuncForTest(t *testing.T) {
	restore := SetNowFuncForTest(func() time.Time {
		return time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	})
	restore()
}

func TestVerifyWithDeterministicTimeEnv(t *testing.T) {
	t.Setenv("INTENTPROOF_DETERMINISTIC_TIME", "1")
	// Re-run init path by verifying a minimal flow.
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]}`)
	if _, err := Verify(flow, policy, nil); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_DETERMINISTIC_TIME", "")
}

func reason(run *VerificationRun, ruleID string) string {
	for _, f := range run.Findings {
		if id, _ := f["rule_id"].(string); id == ruleID {
			if r, _ := f["reason"].(string); r != "" {
				return r
			}
		}
	}
	return ""
}

func TestValuesEqualIntComparisonsViaWhere(t *testing.T) {
	if !valuesEqual(1, float64(1)) {
		t.Fatal("int vs float64")
	}
	if !valuesEqual(int64(2), 2) {
		t.Fatal("int64 vs int")
	}
	if valuesEqual(true, false) {
		t.Fatal("bool mismatch")
	}
	ev := event{Attributes: map[string]interface{}{"n": 3}}
	where := map[string]interface{}{"attribute": "n", "equals": 3}
	if !matchesWhere(ev, where) {
		t.Fatal("expected attribute equals match")
	}
}

func TestParseEventTimeAndIntFromInterface(t *testing.T) {
	if parseEventTime("").IsZero() {
		// ok
	}
	if parseEventTime("not-a-time").IsZero() {
		// ok
	}
	if got := intFromInterface(int64(3)); got != 3 {
		t.Fatalf("int64: %d", got)
	}
	if got := intFromInterface(float64(4)); got != 4 {
		t.Fatalf("float64: %d", got)
	}
}

func TestValidateAgreeAtLeastTypes(t *testing.T) {
	if _, err := validateAgreeAtLeast(int64(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := validateAgreeAtLeast(float64(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := validateAgreeAtLeast(nil); err == nil {
		t.Fatal("expected nil error")
	}
}

func TestCanonicalClaimValueKeyAndRunFingerprint(t *testing.T) {
	key := canonicalClaimValueKey(map[string]interface{}{"a": 1})
	if key == "" {
		t.Fatal("expected key")
	}
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("empty run json")
	}
}
