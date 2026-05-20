package verifier

import (
	"strings"
	"testing"
)

func TestValuesEqualCrossNumericTypes(t *testing.T) {
	cases := []struct {
		a, b   interface{}
		wantOK bool
	}{
		{1, float64(1), true},
		{int64(2), 2, true},
		{float64(3), int64(3), true},
		{"x", 1, false},
		{true, true, true},
		{nil, nil, true},
	}
	for _, tc := range cases {
		if got := valuesEqual(tc.a, tc.b); got != tc.wantOK {
			t.Fatalf("valuesEqual(%#v,%#v)=%v want %v", tc.a, tc.b, got, tc.wantOK)
		}
	}
}

func TestValidateAgreeAtLeastRejectsFractional(t *testing.T) {
	if _, err := validateAgreeAtLeast(float64(1.5)); err == nil {
		t.Fatal("expected fractional error")
	}
}

func TestValidateAgreeAtLeastRejectsNonNumeric(t *testing.T) {
	if _, err := validateAgreeAtLeast("two"); err == nil {
		t.Fatal("expected type error")
	}
}

func TestVerifyTenantMismatch(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt_a","flow_merkle_root":"sha256:0","events":[]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt_b","policy_version":1,"rules":[]}`)
	_, err := Verify(flow, policy, nil)
	if err == nil || !strings.Contains(err.Error(), "tenant mismatch") {
		t.Fatalf("err=%v", err)
	}
}

func TestParseAttestationsRejectsBadLine(t *testing.T) {
	if _, err := parseAttestations([]byte("{not json}\n")); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestRequiredRuleOverMax(t *testing.T) {
	flow := []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[
  {"event_id":"e1","action":"pay","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"},
  {"event_id":"e2","action":"pay","status":"ok","started_at":"2026-05-12T00:00:02Z","completed_at":"2026-05-12T00:00:03Z"}
]}`)
	policy := []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{
  "id":"r1","category":"required","severity":"medium","spec":{"action":"pay","min":1,"max":1}
}]}`)
	run, err := Verify(flow, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reason(run, "r1") != "fail.required.over_max" {
		t.Fatalf("%+v", run.Findings)
	}
}
