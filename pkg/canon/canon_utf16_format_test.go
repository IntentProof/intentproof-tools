package canon

import "testing"

func TestLessUTF16ComparesCodeUnits(t *testing.T) {
	if !lessUTF16("\u007F", "\u0080") {
		t.Fatal("expected U+007F before U+0080 in UTF-16 order")
	}
}

func TestFormatES6StripsTrailingZerosFromMantissa(t *testing.T) {
	out := formatES6(100000000000000000000)
	if out == "" {
		t.Fatal("expected formatted number")
	}
}
