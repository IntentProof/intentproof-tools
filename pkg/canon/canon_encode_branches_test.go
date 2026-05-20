package canon

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestEncodeValueEncodesFalseBoolean(t *testing.T) {
	var buf bytes.Buffer
	if err := encodeValue(&buf, false); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "false" {
		t.Fatalf("out=%s", buf.String())
	}
}

func TestEncodeValueRejectsUnsupportedGoType(t *testing.T) {
	var buf bytes.Buffer
	if err := encodeValue(&buf, make(chan int)); err == nil {
		t.Fatal("expected unsupported type error")
	}
}

func TestLessUTF16OrdersBySecondSurrogateUnit(t *testing.T) {
	a := string(rune(0x10000))
	b := string(rune(0x10001))
	if !lessUTF16(a, b) {
		t.Fatal("expected a < b by second unit")
	}
	if lessUTF16(b, a) {
		t.Fatal("expected b > a")
	}
}

func TestEncodeStringRejectsInvalidUTF8(t *testing.T) {
	var buf bytes.Buffer
	if err := encodeString(&buf, string([]byte{0xff, 0xfe, 0xfd})); err == nil {
		t.Fatal("expected invalid UTF-8 error")
	}
}

func TestFormatES6NegativeDecimal(t *testing.T) {
	out := formatES6(-12.5)
	if !strings.HasPrefix(out, "-") {
		t.Fatalf("out=%s", out)
	}
}

func TestEncodeNumberBeyondSafeIntegerUsesFloatPath(t *testing.T) {
	var buf bytes.Buffer
	if err := encodeNumber(&buf, json.Number("9007199254740993")); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("empty")
	}
}
