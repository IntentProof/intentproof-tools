package verifier

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCanonicalRunJSONStripsMutableFields(t *testing.T) {
	run := &VerificationRun{
		RunID:          "r1",
		FlowID:         "f1",
		Status:         "pass",
		RunFingerprint: "sha256:abc",
		StartedAt:      time.Now().Format(time.RFC3339),
		CompletedAt:    time.Now().Format(time.RFC3339),
		Findings:       []map[string]any{},
	}
	raw, err := CanonicalRunJSON(run)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "run_fingerprint") {
		t.Fatalf("raw=%s", raw)
	}
}

func TestParseISODurationFormats(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"PT5M", 5 * time.Minute},
		{"PT1H30M", 90 * time.Minute},
		{"PT30S", 30 * time.Second},
		{"500ms", 500 * time.Millisecond},
	}
	for _, tc := range cases {
		got, err := parseISODuration(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("%s: got %v want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseISODurationErrors(t *testing.T) {
	for _, in := range []string{"", "P1D", "PX"} {
		if _, err := parseISODuration(in); err == nil {
			t.Fatalf("expected error for %q", in)
		}
	}
}


func TestVerifyInvalidFlowJSON(t *testing.T) {
	_, err := Verify([]byte("{"), []byte(`{"policy_id":"p","tenant_id":"t","policy_version":1,"rules":[]}`), nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestVerifyInvalidPolicyJSON(t *testing.T) {
	flow, _ := json.Marshal(map[string]any{
		"flow_id": "f1", "tenant_id": "tnt", "flow_merkle_root": "sha256:0", "events": []any{},
	})
	_, err := Verify(flow, []byte("{"), nil)
	if err == nil {
		t.Fatal("expected error")
	}
}
