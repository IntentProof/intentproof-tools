package bundle

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestExplainFromReaderPass(t *testing.T) {
	t.Setenv("INTENTPROOF_DETERMINISTIC_TIME", "1")
	buf := mustTestBundleBytes(t)
	text, code, err := ExplainFromReader(bytes.NewReader(buf), nil)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("code=%d text=%s", code, text)
	}
	if !strings.Contains(text, "bundle.verify_pass") {
		t.Fatalf("text=%s", text)
	}
	if !strings.Contains(text, "Policy replay") {
		t.Fatalf("missing replay section: %s", text)
	}
}

func TestExplainFromReaderInvalidBundle(t *testing.T) {
	_, code, err := ExplainFromReader(bytes.NewReader([]byte("not-a-bundle")), nil)
	if err == nil || code != 1 {
		t.Fatalf("err=%v code=%d", err, code)
	}
}

func TestExplainFromReaderIntegrityFail(t *testing.T) {
	buf := mustTestBundleBytes(t)
	b, err := Read(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	b.RawFiles["events.jsonl"] = []byte("tampered\n")
	var out bytes.Buffer
	if err := writeBundle(&out, b); err != nil {
		t.Fatal(err)
	}
	text, code, err := ExplainFromReader(bytes.NewReader(out.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if code != 1 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(text, "Integrity findings") {
		t.Fatalf("text=%s", text)
	}
}

func TestVerifyBundleWrapper(t *testing.T) {
	buf := mustTestBundleBytes(t)
	b, err := Read(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	vr, err := VerifyBundle(b, nil)
	if err != nil || vr.Status != "pass" {
		t.Fatalf("vr=%v err=%v", vr, err)
	}
}

func TestFormatExplainBundledRunFindingsOnly(t *testing.T) {
	describe := func(code string) (string, string, bool) {
		return "Title for " + code, "Detail", true
	}
	out := FormatExplain(
		&VerifyResult{Status: "fail", Reason: "bundle.file_missing"},
		map[string]interface{}{
			"status": "fail",
			"findings": []interface{}{
				map[string]interface{}{
					"outcome": "fail",
					"reason":  "fail.required.missing",
				},
			},
		},
		nil,
		describe,
	)
	for _, part := range []string{
		"Policy findings (from bundled run.json)",
		"fail.required.missing",
		"Title for fail.required.missing",
		"Detail",
	} {
		if !strings.Contains(out, part) {
			t.Fatalf("missing %q in %s", part, out)
		}
	}
}

func TestReplayPolicyWithAttestations(t *testing.T) {
	t.Setenv("INTENTPROOF_DETERMINISTIC_TIME", "1")
	flowJSON, _ := json.Marshal(map[string]interface{}{
		"flow_id":          "flow_att",
		"tenant_id":        "tnt_test",
		"flow_merkle_root": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	})
	eventsJSONL := []byte("{\"event_id\":\"evt_1\",\"action\":\"pay\",\"status\":\"ok\"}\n")
	attsJSONL := []byte("{\"attestation_id\":\"a1\",\"claim\":\"refund.ok\",\"claim_value\":true}\n")
	policyJSON := []byte(`{"policy_id":"p1","tenant_id":"tnt_test","policy_version":1,"rules":[]}`)
	runJSON := []byte(`{"status":"pass","findings":[]}`)

	var buf bytes.Buffer
	if err := Create(&buf, CreateOptions{
		BundleID:          "bnd_att",
		FlowID:            "flow_att",
		TenantID:          "tnt_test",
		FlowJSON:          flowJSON,
		EventsJSONL:       eventsJSONL,
		AttestationsJSONL: attsJSONL,
		PolicyJSON:        policyJSON,
		RunJSON:           runJSON,
	}); err != nil {
		t.Fatal(err)
	}
	b, err := Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayPolicy(b); err != nil {
		t.Fatal(err)
	}
}

func TestExplainFromReaderReplayStatusFail(t *testing.T) {
	t.Setenv("INTENTPROOF_DETERMINISTIC_TIME", "1")
	policyJSON := []byte(`{
  "policy_id": "p1",
  "tenant_id": "tnt_test",
  "policy_version": 1,
  "rules": [{"id":"r1","category":"unknown_cat","severity":"high","spec":{}}]
}`)
	flowJSON, _ := json.Marshal(map[string]interface{}{
		"flow_id": "f1", "tenant_id": "tnt_test",
		"flow_merkle_root": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	})
	var buf bytes.Buffer
	if err := Create(&buf, CreateOptions{
		BundleID: "bnd_inc", FlowID: "f1", TenantID: "tnt_test",
		FlowJSON: flowJSON, EventsJSONL: []byte("{\"event_id\":\"e1\",\"action\":\"a\",\"status\":\"ok\"}\n"),
		PolicyJSON: policyJSON, RunJSON: []byte(`{"status":"pass","findings":[]}`),
	}); err != nil {
		t.Fatal(err)
	}
	_, code, err := ExplainFromReader(bytes.NewReader(buf.Bytes()), nil)
	if err != nil || code != 1 {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

func TestFormatExplainReplayStatusDiffers(t *testing.T) {
	replay := NewVerifierRunView("fail", []map[string]interface{}{
		{"outcome": "fail", "reason": "fail.x"},
	})
	out := FormatExplain(
		&VerifyResult{Status: "pass", Reason: "bundle.verify_pass"},
		map[string]interface{}{"status": "pass"},
		replay,
		nil,
	)
	if !strings.Contains(out, "differs from bundled run.json") {
		t.Fatalf("out=%s", out)
	}
}

func TestReplayPolicyErrors(t *testing.T) {
	if _, err := ReplayPolicy(nil); err == nil {
		t.Fatal("expected nil bundle error")
	}
	b := &Bundle{Flow: map[string]interface{}{"flow_id": "f"}}
	if _, err := ReplayPolicy(b); err == nil {
		t.Fatal("expected missing policy error")
	}
}

func TestBundledRunStatusEdges(t *testing.T) {
	if _, ok := BundledRunStatus(nil); ok {
		t.Fatal("nil bundle")
	}
	b := &Bundle{Run: map[string]interface{}{"status": ""}}
	if _, ok := BundledRunStatus(b); ok {
		t.Fatal("empty status")
	}
}

func TestPolicyFindingsFromRunSkipsInvalid(t *testing.T) {
	run := map[string]interface{}{
		"findings": []interface{}{"not-a-map", map[string]interface{}{
			"outcome": "fail", "reason": "fail.a",
		}},
	}
	got := policyFindingsFromRun(run)
	if len(got) != 1 || got[0].Reason != "fail.a" {
		t.Fatalf("got=%v", got)
	}
}

func mustTestBundleBytes(t *testing.T) []byte {
	t.Helper()
	t.Setenv("INTENTPROOF_DETERMINISTIC_TIME", "1")
	flowJSON, _ := json.Marshal(map[string]interface{}{
		"flow_id":          "flow_explain",
		"tenant_id":        "tnt_test",
		"flow_merkle_root": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	})
	eventsJSONL := []byte("{\"event_id\":\"evt_1\",\"action\":\"pay\",\"status\":\"ok\"}\n")
	policyJSON := []byte(`{"policy_id":"p1","tenant_id":"tnt_test","policy_version":1,"rules":[]}`)
	runJSON := []byte(`{"status":"pass","findings":[]}`)

	var buf bytes.Buffer
	if err := Create(&buf, CreateOptions{
		BundleID:    "bnd_explain",
		FlowID:      "flow_explain",
		TenantID:    "tnt_test",
		FlowJSON:    flowJSON,
		EventsJSONL: eventsJSONL,
		PolicyJSON:  policyJSON,
		RunJSON:     runJSON,
	}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
