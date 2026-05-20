package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
)

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	return 0, errors.New("write refused")
}

func TestCreateTarWriteError(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	err := Create(shortWriter{}, opts)
	if err == nil {
		t.Fatal("expected write error")
	}
}

func TestVerifySignedMapEnvelopeMarshalError(t *testing.T) {
	doc := map[string]interface{}{
		"event_id":  "e1",
		"signature": make(chan int),
	}
	findings, err := verifySignedMap(&Bundle{PublicKeys: map[string][]byte{}}, nil,
		"event", "signature", doc, []string{"signature"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "event.signature_decode_failed") {
		t.Fatalf("findings=%v", findings)
	}
}

func TestCanonicalSignedMapRejectUnsupportedValue(t *testing.T) {
	doc := map[string]interface{}{
		"event_id": "e1",
		"bad":      make(chan int),
	}
	_, err := canonicalSignedMap(doc, []string{"bad"})
	if err == nil {
		t.Fatal("expected canonicalize error")
	}
}

func TestVerifyObjectSignaturesReturnsCanonicalizeError(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := map[string]interface{}{"event_id": "e1"}
	payload, err := canonicalSignedMap(ev, []string{"signature"})
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, sha256sum(payload))
	ev["signature"] = map[string]interface{}{
		"alg": "ed25519", "key_id": "k1",
		"value": hex.EncodeToString(sig),
	}
	ev["bad"] = make(chan int)
	b := &Bundle{
		PublicKeys: map[string][]byte{"k1": pub},
		Events:     []map[string]interface{}{ev},
	}
	_, err = verifyObjectSignatures(b, nil)
	if err == nil {
		t.Fatal("expected canonicalize error")
	}
}
