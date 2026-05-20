package canon

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"
)

func TestMarshalSortsObjectKeysDeterministically(t *testing.T) {
	raw, err := Marshal(map[string]any{
		"z": 1,
		"a": 2,
		"m": 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"a":2,"m":3,"z":1}` {
		t.Fatalf("raw=%s", raw)
	}
}

func TestMarshalRejectsNonFiniteNumber(t *testing.T) {
	_, err := Marshal(map[string]any{"x": math.Inf(1)})
	if err == nil {
		t.Fatal("expected non-finite error")
	}
}

func TestMarshalRawRejectsTrailingToken(t *testing.T) {
	_, err := MarshalRaw(json.RawMessage(`{"a":1}{"b":2}`))
	if err == nil {
		t.Fatal("expected trailing token error")
	}
}

func TestMarshalRawRejectsMalformedSuffix(t *testing.T) {
	_, err := MarshalRaw(json.RawMessage(`{"a":1}x`))
	if err == nil {
		t.Fatal("expected malformed suffix error")
	}
}

func TestDecodeValueRejectsNonStringObjectKeyViaDecoder(t *testing.T) {
	dec := json.NewDecoder(bytes.NewReader([]byte(`{"ok":1}`)))
	dec.UseNumber()
	if _, err := decodeValue(dec); err != nil {
		t.Fatal(err)
	}
}
