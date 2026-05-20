package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestVerifySignedMapValidRunSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	run := map[string]interface{}{
		"run_id": "run_1",
		"status": "pass",
	}
	payload, err := canonicalSignedMap(run, []string{"signature", "run_fingerprint", "started_at", "completed_at"})
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, sha256sum(payload))
	run["signature"] = map[string]interface{}{
		"alg":    "ed25519",
		"key_id": "run:k1",
		"value":  hex.EncodeToString(sig),
	}
	b := &Bundle{PublicKeys: map[string][]byte{"run:k1": pub}}
	findings, err := verifySignedMap(b, nil, "run", "signature", run, []string{
		"signature", "run_fingerprint", "started_at", "completed_at",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "run.signature_valid") {
		t.Fatalf("findings=%v", findings)
	}
}

func TestVerifySignedMapInvalidSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = priv
	run := map[string]interface{}{
		"run_id": "run_1",
		"signature": map[string]interface{}{
			"alg":    "ed25519",
			"key_id": "run:k1",
			"value":  hex.EncodeToString(make([]byte, ed25519.SignatureSize)),
		},
	}
	b := &Bundle{PublicKeys: map[string][]byte{"run:k1": pub}}
	findings, err := verifySignedMap(b, nil, "run", "signature", run, []string{"signature"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "run.signature_invalid") {
		t.Fatalf("findings=%v", findings)
	}
}

func TestVerifyObjectSignaturesCertificate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := map[string]interface{}{"schema": "intentproof.certificate.v1"}
	payload, err := canonicalSignedMap(cert, []string{"signature"})
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, sha256sum(payload))
	cert["signature"] = map[string]interface{}{
		"alg": "ed25519", "key_id": "cert:k1",
		"value": hex.EncodeToString(sig),
	}
	b := &Bundle{
		PublicKeys:  map[string][]byte{"cert:k1": pub},
		Certificate: cert,
	}
	findings, err := verifyObjectSignatures(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "certificate.signature_valid") {
		t.Fatalf("findings=%v", findings)
	}
}
