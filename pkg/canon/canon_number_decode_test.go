package canon

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"
)

func TestEncodeNumberEdgeCases(t *testing.T) {
	cases := []string{"0", "-0", "9007199254740991", "0.000001", "1e3"}
	for _, s := range cases {
		t.Run(s, func(t *testing.T) {
			var buf bytes.Buffer
			if err := encodeNumber(&buf, json.Number(s)); err != nil {
				t.Fatal(err)
			}
			if buf.Len() == 0 {
				t.Fatal("empty output")
			}
		})
	}
}

func TestEncodeNumberRejectsEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := encodeNumber(&buf, json.Number("")); err == nil {
		t.Fatal("expected empty number error")
	}
}

func TestEncodeNumberRejectsNaNString(t *testing.T) {
	var buf bytes.Buffer
	if err := encodeNumber(&buf, json.Number("NaN")); err == nil {
		t.Fatal("expected NaN error")
	}
}

func TestEncodeNumberRejectsInfinityString(t *testing.T) {
	var buf bytes.Buffer
	if err := encodeNumber(&buf, json.Number("Infinity")); err == nil {
		t.Fatal("expected infinity error")
	}
	_ = math.MaxFloat64
}


func TestLessUTF16Ordering(t *testing.T) {
	if !lessUTF16("a", "b") {
		t.Fatal("expected a < b")
	}
	if lessUTF16("b", "a") {
		t.Fatal("expected b > a")
	}
}
