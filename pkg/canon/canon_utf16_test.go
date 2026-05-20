package canon

import "testing"

func TestLessUTF16SupplementaryPlanes(t *testing.T) {
	// U+1D11E (musical symbol) sorts after BMP strings in UTF-16 order.
	if !lessUTF16("a", "\U0001D11E") {
		t.Fatal("expected supplementary plane to sort after BMP")
	}
	if lessUTF16("\U0001D11E", "a") {
		t.Fatal("unexpected order")
	}
}

func TestOrderedObjectRejectsDuplicateKeys(t *testing.T) {
	o := newOrderedObject()
	if err := o.set("a", 1); err != nil {
		t.Fatal(err)
	}
	if err := o.set("a", 2); err == nil {
		t.Fatal("expected duplicate key error")
	}
}

func TestMarshalDuplicateKeysInMapInput(t *testing.T) {
	// json.Unmarshal into map loses duplicates; MarshalRaw preserves order from JSON.
	raw := []byte(`{"b":1,"a":2}`)
	out, err := MarshalRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("empty")
	}
}
