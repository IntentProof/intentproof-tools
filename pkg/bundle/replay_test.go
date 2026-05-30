package bundle

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestReplayPolicyFromBundle(t *testing.T) {
	t.Setenv("INTENTPROOF_DETERMINISTIC_TIME", "1")
	flowJSON, _ := json.Marshal(map[string]interface{}{
		"flow_id":          "flow_replay_test",
		"tenant_id":        "tnt_test",
		"flow_merkle_root": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	})
	eventsJSONL := []byte("{\"event_id\":\"evt_1\",\"action\":\"stripe.refund.create\",\"status\":\"ok\"}\n")
	policyJSON := []byte(`{
  "policy_id": "pol_test",
  "tenant_id": "tnt_test",
  "policy_version": 1,
  "rules": []
}`)
	runJSON := []byte(`{"status":"pass","findings":[]}`)

	var buf bytes.Buffer
	if err := Create(&buf, CreateOptions{
		BundleID:    "bnd_replay_test",
		FlowID:      "flow_replay_test",
		TenantID:    "tnt_test",
		FlowJSON:    flowJSON,
		EventsJSONL: eventsJSONL,
		PolicyJSON:  policyJSON,
		RunJSON:     runJSON,
	}); err != nil {
		t.Fatal(err)
	}

	b, err := Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	run, err := ReplayPolicy(b)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "pass" {
		t.Fatalf("replay status=%s", run.Status)
	}
	status, ok := BundledRunStatus(b)
	if !ok || status != "pass" {
		t.Fatalf("bundled status=%q ok=%v", status, ok)
	}
}
