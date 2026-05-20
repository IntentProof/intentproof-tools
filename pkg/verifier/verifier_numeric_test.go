package verifier

import "testing"

func TestToFloat64Branches(t *testing.T) {
	if v, ok := toFloat64(int64(3)); !ok || v != 3 {
		t.Fatalf("int64: %v %v", v, ok)
	}
	if v, ok := toFloat64(float64(2.5)); !ok || v != 2.5 {
		t.Fatalf("float64: %v %v", v, ok)
	}
	if _, ok := toFloat64("nope"); ok {
		t.Fatal("string should fail")
	}
}

func TestIntFromInterfaceBranches(t *testing.T) {
	if got := intFromInterface(float64(4)); got != 4 {
		t.Fatalf("float64: %d", got)
	}
	if got := intFromInterface(int64(5)); got != 5 {
		t.Fatalf("int64: %d", got)
	}
	if got := intFromInterface("x"); got != 0 {
		t.Fatalf("default: %d", got)
	}
}

func TestValuesEqualNumericBranches(t *testing.T) {
	if !valuesEqual(1, float64(1)) {
		t.Fatal("int/float")
	}
	if valuesEqual(1, 2) {
		t.Fatal("unequal")
	}
}

func TestValidateAgreeAtLeast(t *testing.T) {
	if n, err := validateAgreeAtLeast(2); err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if _, err := validateAgreeAtLeast(0); err == nil {
		t.Fatal("expected error")
	}
}
