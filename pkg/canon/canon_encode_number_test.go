package canon

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestMarshalNestedArrayEncodeFailure(t *testing.T) {
	_, err := Marshal(map[string]any{
		"items": []any{json.Number("1"), make(chan int)},
	})
	if err == nil {
		t.Fatal("expected nested encode error")
	}
}

func TestEncodeNumberRejectsInvalidJSONNumber(t *testing.T) {
	var buf bytes.Buffer
	err := encodeNumber(&buf, json.Number("not-a-number"))
	if err == nil {
		t.Fatal("expected invalid number error")
	}
}

func TestEncodeNumberRejectsNaN(t *testing.T) {
	var buf bytes.Buffer
	err := encodeNumber(&buf, json.Number("NaN"))
	if err == nil || !strings.Contains(err.Error(), "non-finite") {
		t.Fatalf("err=%v", err)
	}
}

func TestDecodeValueRejectsUnexpectedDelimiter(t *testing.T) {
	dec := json.NewDecoder(strings.NewReader(")"))
	dec.UseNumber()
	if _, err := decodeValue(dec); err == nil {
		t.Fatal("expected delimiter error")
	}
}
