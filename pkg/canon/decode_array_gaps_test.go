package canon

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestDecodeValueReadsArrayElements(t *testing.T) {
	dec := json.NewDecoder(bytes.NewReader([]byte(`[1,"x",true,null]`)))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		t.Fatal(err)
	}
	arr, ok := v.([]any)
	if !ok || len(arr) != 4 {
		t.Fatalf("v=%#v", v)
	}
}

func TestEncodeObjectSkipsEmptyNestedObject(t *testing.T) {
	raw, err := Marshal(map[string]any{
		"outer": map[string]any{
			"inner": map[string]any{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"outer"`)) {
		t.Fatalf("raw=%s", raw)
	}
}

func TestDecodeValueRejectsInvalidArrayToken(t *testing.T) {
	dec := json.NewDecoder(bytes.NewReader([]byte(`[1,`)))
	dec.UseNumber()
	if _, err := decodeValue(dec); err == nil {
		t.Fatal("expected array decode error")
	}
}
