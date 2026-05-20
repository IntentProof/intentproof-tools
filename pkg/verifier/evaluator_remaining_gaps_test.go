package verifier

import "testing"

func TestValuesEqualRejectsMixedTypes(t *testing.T) {
	cases := []struct {
		a, b interface{}
	}{
		{float64(1), "1"},
		{int(1), true},
		{int64(2), "2"},
		{true, 1},
		{"x", nil},
		{nil, "x"},
		{float64(1), int(2)},
	}
	for _, tc := range cases {
		if valuesEqual(tc.a, tc.b) {
			t.Fatalf("valuesEqual(%#v,%#v) expected false", tc.a, tc.b)
		}
	}
}

func TestValuesEqualInt64FloatCrossTypes(t *testing.T) {
	if !valuesEqual(int64(5), float64(5)) {
		t.Fatal("expected int64/float64 equality")
	}
	if !valuesEqual(int(7), int64(7)) {
		t.Fatal("expected int/int64 equality")
	}
}

func TestToFloat64FromStringFails(t *testing.T) {
	if _, ok := toFloat64("nope"); ok {
		t.Fatal("expected false")
	}
}

func TestIntFromInterfaceCoercesNumericTypes(t *testing.T) {
	if got := intFromInterface(int64(3)); got != 3 {
		t.Fatalf("got=%d", got)
	}
	if got := intFromInterface(float64(4)); got != 4 {
		t.Fatalf("got=%d", got)
	}
	if got := intFromInterface("nope"); got != 0 {
		t.Fatalf("got=%d", got)
	}
}

func TestFilterAttestationsByClaimAndSource(t *testing.T) {
	atts := []attestation{
		{AttestationID: "a1", Claim: "mode", SourceID: "platform"},
		{AttestationID: "a2", Claim: "mode", SourceID: "sdk"},
		{AttestationID: "a3", Claim: "other", SourceID: "platform"},
	}
	filtered := filterAttestations(atts, "mode", "platform")
	if len(filtered) != 1 || filtered[0].AttestationID != "a1" {
		t.Fatalf("filtered=%+v", filtered)
	}
}

func TestComputeRunFingerprintIncludesFindings(t *testing.T) {
	run := &VerificationRun{
		RunID:  "run_1",
		FlowID: "flow_1",
		Status: "fail",
		Findings: []map[string]interface{}{
			{"rule_id": "r1", "reason": "fail.required.missing"},
		},
	}
	fp, err := computeRunFingerprint(run)
	if err != nil || fp == "" {
		t.Fatalf("fp=%q err=%v", fp, err)
	}
}
