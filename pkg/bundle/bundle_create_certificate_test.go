package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestCreateSignerSuccessUsesHexSignature(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opts := buildTestBundleOpts(t, nil)
	opts.Signer = func(data []byte) (*SignatureEnvelope, error) {
		sig := ed25519.Sign(priv, sha256Sum(data))
		return &SignatureEnvelope{Alg: "ed25519", KeyID: "k1", Value: hex.EncodeToString(sig)}, nil
	}
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(&buf, priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "pass" {
		t.Fatalf("status=%s", res.Status)
	}
}

func TestJsonlBytesMultipleItems(t *testing.T) {
	out := jsonlBytes([]map[string]any{{"a": 1}, {"b": 2}})
	if !bytes.Contains(out, []byte("\n")) {
		t.Fatalf("expected newline between items, got %q", out)
	}
}
