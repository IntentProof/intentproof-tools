package canon

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestMarshalRejectsMalformedTrailingJSON(t *testing.T) {
	_, err := Marshal(json.RawMessage(`{"a":1}{`))
	if err == nil {
		t.Fatal("expected trailing json error")
	}
}

func TestDecodeValueRejectsNonStringObjectKey(t *testing.T) {
	dec := json.NewDecoder(bytes.NewReader([]byte(`{1:"x"}`)))
	dec.UseNumber()
	if _, err := decodeValue(dec); err == nil {
		t.Fatal("expected object key error")
	}
}

func TestDecodeValueRejectsInvalidObjectClose(t *testing.T) {
	dec := json.NewDecoder(bytes.NewReader([]byte(`{"a":1`)))
	dec.UseNumber()
	if _, err := decodeValue(dec); err == nil {
		t.Fatal("expected object decode error")
	}
}

func TestEncodeValueRejectsUnsupportedType(t *testing.T) {
	var buf bytes.Buffer
	if err := encodeValue(&buf, make(chan int)); err == nil {
		t.Fatal("expected encode error")
	}
}

func TestDecodeValueRejectsInvalidArrayClose(t *testing.T) {
	dec := json.NewDecoder(bytes.NewReader([]byte(`[1,2`)))
	dec.UseNumber()
	if _, err := decodeValue(dec); err == nil {
		t.Fatal("expected array decode error")
	}
}

func TestOrderedObjectSetRejectsDuplicateKey(t *testing.T) {
	obj := newOrderedObject()
	if err := obj.set("a", 1); err != nil {
		t.Fatal(err)
	}
	if err := obj.set("a", 2); err == nil {
		t.Fatal("expected duplicate key error")
	}
}
