package verifier

import (
	"encoding/json"
	"testing"
)

// Exercises consensus agree_at_least, event where filters, and typed value equality.
func TestVerifyConsensusAgreeAtLeastAndWhereFilters(t *testing.T) {
	flow := []byte(`{
  "flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000",
  "events":[
    {"event_id":"e1","action":"pay","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z","attributes":{"tier":"gold"}},
    {"event_id":"e2","action":"pay","status":"fail","started_at":"2026-05-12T00:00:02Z","completed_at":"2026-05-12T00:00:03Z","attributes":{"tier":"silver"}}
  ]
}`)
	atts := []byte(`{"attestation_id":"a1","claim":"risk.score","claim_value":0.5,"source_id":"model-a"}
{"attestation_id":"a2","claim":"risk.score","claim_value":0.5,"source_id":"model-b"}
{"attestation_id":"a3","claim":"risk.score","claim_value":0.9,"source_id":"model-c"}
`)

	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[
  {"id":"consensus","category":"consensus","severity":"high","spec":{
    "claim":"risk.score","threshold":{"agree_at_least":3}
  }},
  {"id":"where-required","category":"required","severity":"medium","spec":{
    "action":"pay","min":1,"where":{"status":"ok","attribute":"tier","equals":"gold"}
  }},
  {"id":"cardinality","category":"cardinality","severity":"medium","spec":{
    "action":"pay","exactly":2,"where":{"attribute":"tier","in":["gold","silver"]}
  }}
]}`)

	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != "fail" {
		t.Fatalf("expected fail due to consensus, got %s", run.Status)
	}
	reasons := map[string]bool{}
	for _, f := range run.Findings {
		if r, ok := f["reason"].(string); ok {
			reasons[r] = true
		}
	}
	if !reasons["fail.consensus.disagreement"] {
		t.Fatalf("missing consensus disagreement: %+v", run.Findings)
	}
	if !reasons["pass.cardinality.satisfied"] && !reasons["pass.required.satisfied"] {
		t.Fatalf("expected passing non-consensus rules: %+v", run.Findings)
	}
}

func TestVerifyConsensusMajorityWithoutExpectedValue(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[]}`)
	atts := []byte(`{"attestation_id":"a1","claim":"flag","claim_value":true}
{"attestation_id":"a2","claim":"flag","claim_value":true}
{"attestation_id":"a3","claim":"flag","claim_value":false}
`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"consensus","severity":"high",
  "spec":{"claim":"flag","threshold":{"majority":true}}
}]}`)

	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "pass" {
		t.Fatalf("expected pass, got %s findings=%v", run.Status, run.Findings)
	}
}

func TestVerifyInvalidAgreeAtLeastThreshold(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[]}`)
	atts := []byte(`{"attestation_id":"a1","claim":"x","claim_value":1}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"consensus","severity":"high",
  "spec":{"claim":"x","threshold":{"agree_at_least":0}}
}]}`)
	run, err := Verify(flow, policy, atts)
	if err != nil {
		t.Fatal(err)
	}
	if findReason(run.Findings, "r1") != "fail.consensus.insufficient" {
		t.Fatalf("findings=%+v", run.Findings)
	}
}

func TestCanonicalRunJSONAndParseISODuration(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[
  {"event_id":"e1","action":"a","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:05Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"temporal","category":"temporal","severity":"medium",
  "spec":{"from":{"action":"a"},"to":{"action":"a"},"max_duration":"PT5S"}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CanonicalRunJSON(run)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) {
		t.Fatalf("invalid canonical json: %s", raw)
	}
}

func findReason(findings []map[string]interface{}, ruleID string) string {
	for _, f := range findings {
		if id, _ := f["rule_id"].(string); id == ruleID {
			if r, _ := f["reason"].(string); r != "" {
				return r
			}
		}
	}
	return ""
}
