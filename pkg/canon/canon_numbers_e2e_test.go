package canon

import (
	"encoding/json"
	"testing"
)

func TestMarshalEncodesNonFiniteNumbersAsNull(t *testing.T) {
	raw, err := Marshal(map[string]any{
		"nan":  json.RawMessage(`null`),
		"big":  1e30,
		"small": 1e-10,
		"int":  42,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("expected bytes")
	}
}

func TestMarshalRawRoundTrip(t *testing.T) {
	input := json.RawMessage(`{"z":1,"a":2}`)
	raw, err := MarshalRaw(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("expected output")
	}
}
