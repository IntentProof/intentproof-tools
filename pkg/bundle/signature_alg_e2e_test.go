package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestVerifyEmbeddedObjectUnsupportedAlg(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	event := map[string]interface{}{
		"event_id": "e1",
		"action":   "pay",
		"status":   "ok",
		"signature": map[string]interface{}{
			"alg":    "rsa-4096",
			"key_id": "object:k1",
			"value":  "c2ln",
		},
	}
	opts := buildTestBundleOpts(t, nil)
	opts.EventsJSONL = jsonlBytes([]map[string]interface{}{event})
	opts.PublicKeys = map[string][]byte{"object:k1": pub}
	_ = priv

	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(res.Findings, "event.signature_unsupported_alg") {
		t.Fatalf("findings=%v", res.Findings)
	}
}

func TestVerifyEmbeddedObjectKeyUnavailable(t *testing.T) {
	event := map[string]interface{}{
		"event_id": "e1",
		"action":   "pay",
		"status":   "ok",
		"signature": map[string]interface{}{
			"alg":    "ed25519",
			"key_id": "missing",
			"value":  "c2ln",
		},
	}
	opts := buildTestBundleOpts(t, nil)
	opts.EventsJSONL = jsonlBytes([]map[string]interface{}{event})
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(res.Findings, "event.signature_key_unavailable") {
		t.Fatalf("findings=%v", res.Findings)
	}
}

func TestSignatureEnvelopeFromMapInvalid(t *testing.T) {
	_, ok, err := signatureEnvelopeFromMap(map[string]interface{}{
		"signature": make(chan int),
	}, "signature")
	if err == nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}
