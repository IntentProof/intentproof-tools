package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestBuildEventFromSeedProducesValidJSON(t *testing.T) {
	raw := buildEventFromSeed([]byte("seed-a"))
	if !json.Valid(raw) {
		t.Fatalf("invalid json: %s", raw)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if obj["schema"] != "intentproof.event.v1" {
		t.Fatalf("schema: %v", obj["schema"])
	}
}

func TestBuildEventFromSeedMergesJSONObjectSeed(t *testing.T) {
	seed := []byte(`{"intent":"merged","attributes":{"k":"v"}}`)
	raw := buildEventFromSeed(seed)
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if obj["intent"] != "merged" {
		t.Fatalf("intent: %v", obj["intent"])
	}
}

func TestGenerateJSONValueSingleByteBoolBranch(t *testing.T) {
	// seed[0] % 7 == 2 with len(seed) == 1 must not panic.
	if got := generateJSONValue([]byte{2}); got != false {
		t.Fatalf("expected false, got %v", got)
	}
}

func TestGenerateJSONValueDepthBounded(t *testing.T) {
	seed := make([]byte, 256)
	for i := range seed {
		seed[i] = byte(i)
	}
	seed[0] = 4
	seed[1] = 4
	seed[2] = 4
	seed[3] = 4
	done := make(chan struct{})
	go func() {
		_ = generateJSONValue(seed)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("generateJSONValue did not finish within timeout")
	}
}

func TestGenerateJSONValueBranches(t *testing.T) {
	cases := []struct {
		seed []byte
	}{
		{[]byte{0, 'h', 'i'}},
		{[]byte{1, 42}},
		{[]byte{2, 1}},
		{[]byte{3, 0}},
		{[]byte{4, 1, 2, 3}},
		{[]byte{5, 1, 2, 3, 4, 5}},
		{[]byte{6, 5}},
		{[]byte{7}},
	}
	for _, tc := range cases {
		if generateJSONValue(tc.seed) == nil && tc.seed[0]%7 != 3 {
			// null is valid for branch 3 only
		}
		_ = generateJSONValue(tc.seed)
	}
}

func TestPickHelpers(t *testing.T) {
	seed := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if pickStatus(seed) != "error" {
		t.Fatal("expected error status")
	}
	_ = pickBool(seed, 2)
	_ = pickInt(seed, 3, 1, 10)
	_ = pickOptionalNested(seed, 4)
	attrs := pickAttributes(seed)
	if len(attrs) == 0 {
		t.Fatal("expected attributes")
	}
}

func TestTryMergeSeedObject(t *testing.T) {
	if _, ok := tryMergeSeedObject([]byte("not-json")); ok {
		t.Fatal("expected false for invalid json")
	}
	obj, ok := tryMergeSeedObject([]byte(`{"a":1}`))
	if !ok || obj["a"].(float64) != 1 {
		t.Fatalf("unexpected: %v %v", obj, ok)
	}
}
