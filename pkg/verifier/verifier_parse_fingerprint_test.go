package verifier

import (
	"testing"
)

func TestParseISODurationMissingUnitSuffix(t *testing.T) {
	if _, err := parseISODuration("PT5"); err == nil {
		t.Fatal("expected missing unit error")
	}
}

func TestParseISODurationEmptyNumericSegment(t *testing.T) {
	if _, err := parseISODuration("PTX"); err == nil {
		t.Fatal("expected invalid duration error")
	}
}

func TestValidateDeclaredPolicyFingerprintIgnoresNonString(t *testing.T) {
	if err := validateDeclaredPolicyFingerprint(map[string]any{
		"policy_fingerprint": 123,
		"rules":              []any{},
	}); err != nil {
		t.Fatalf("err=%v", err)
	}
}

func TestComputeRunFingerprintCanonicalizeError(t *testing.T) {
	run := &VerificationRun{
		Findings: []map[string]interface{}{
			{"bad": make(chan int)},
		},
	}
	_, err := computeRunFingerprint(run)
	if err == nil {
		t.Fatal("expected canonicalize error")
	}
}

func TestCanonicalRunJSONUnmarshalableAfterMarshal(t *testing.T) {
	run := &VerificationRun{
		Status: "pass",
		Findings: []map[string]interface{}{
			{"reason": "ok"},
		},
	}
	raw, err := CanonicalRunJSON(run)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("expected canonical bytes")
	}
}

func TestToFloat64AcceptsIntType(t *testing.T) {
	if v, ok := toFloat64(int(7)); !ok || v != 7 {
		t.Fatalf("v=%v ok=%v", v, ok)
	}
}

func TestIntFromInterfaceJSONNumber(t *testing.T) {
	if got := intFromInterface(float64(9)); got != 9 {
		t.Fatalf("got=%d", got)
	}
}
