package canon

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestEncodeNumberFormatsNegativeZeroAsZero(t *testing.T) {
	var buf bytes.Buffer
	if err := encodeNumber(&buf, json.Number("-0")); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "0" {
		t.Fatalf("got %q", buf.String())
	}
}

func TestEncodeNumberFormatsLargeFloat(t *testing.T) {
	var buf bytes.Buffer
	if err := encodeNumber(&buf, json.Number("1.23e+20")); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected output")
	}
}

func TestMarshalEncodeFailureAfterDecode(t *testing.T) {
	_, err := Marshal(map[string]any{"nested": map[string]any{"bad": make(chan int)}})
	if err == nil {
		t.Fatal("expected encode failure")
	}
}
