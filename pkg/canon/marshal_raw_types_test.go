package canon

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestMarshalRawNestedArrayAndObject(t *testing.T) {
	raw := json.RawMessage(`{"z":1,"items":[null,false,{"a":"b"}],"empty":[]}`)
	out, err := MarshalRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"items"`) {
		t.Fatalf("out=%s", out)
	}
}

func TestMarshalRawRejectsNonStringObjectKey(t *testing.T) {
	// encoding/json cannot produce non-string keys; exercise unexpected token via number key in manual JSON.
	raw := json.RawMessage(`{1:"bad"}`)
	if _, err := MarshalRaw(raw); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestMarshalRawRejectsTrailingContent(t *testing.T) {
	raw := json.RawMessage(`{} trailing`)
	if _, err := MarshalRaw(raw); err == nil {
		t.Fatal("expected trailing content error")
	}
}

func TestDecodeValueUnexpectedDelimiter(t *testing.T) {
	raw := json.RawMessage(`]`)
	if _, err := MarshalRaw(raw); err == nil {
		t.Fatal("expected delimiter error")
	}
}

func TestMarshalNaNRejected(t *testing.T) {
	if _, err := Marshal(map[string]any{"x": math.NaN()}); err == nil {
		t.Fatal("expected NaN error")
	}
}
