package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestVerifyObjectSignaturesAttestation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := map[string]interface{}{
		"attestation_id": "att_1",
		"platform_signature": map[string]interface{}{
			"alg":    "ed25519",
			"key_id": "att:k1",
			"value":  "",
		},
	}
	payload, err := canonicalSignedMap(att, []string{"platform_signature"})
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, sha256sum(payload))
	att["platform_signature"] = map[string]interface{}{
		"alg":    "ed25519",
		"key_id": "att:k1",
		"value":  hex.EncodeToString(sig),
	}
	b := &Bundle{
		PublicKeys:   map[string][]byte{"att:k1": pub},
		Attestations: []map[string]interface{}{att},
	}
	findings, err := verifyObjectSignatures(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "attestation.signature_valid") {
		t.Fatalf("findings=%v", findings)
	}
}

func TestVerifySignedMapUnsupportedAlg(t *testing.T) {
	doc := map[string]interface{}{
		"signature": map[string]interface{}{
			"alg":    "rsa",
			"key_id": "k1",
			"value":  "aa",
		},
	}
	findings, err := verifySignedMap(&Bundle{PublicKeys: map[string][]byte{"k1": []byte{1}}}, nil,
		"run", "signature", doc, []string{"signature"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "run.signature_unsupported_alg") {
		t.Fatalf("findings=%v", findings)
	}
}

func TestDecodeSignatureValueBase64(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]interface{}{"run_id": "r1"}
	payload, err := canonicalSignedMap(doc, []string{"signature"})
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, sha256sum(payload))
	b64 := base64.StdEncoding.EncodeToString(sig)
	sigBytes, err := decodeSignatureValue(b64)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		t.Fatalf("decode: %v len=%d", err, len(sigBytes))
	}
	findings, err := verifySignedMap(&Bundle{PublicKeys: map[string][]byte{"run:k1": pub}}, nil,
		"run", "signature", map[string]interface{}{
			"run_id": "r1",
			"signature": map[string]interface{}{
				"alg": "ed25519", "key_id": "run:k1",
				"value": b64,
			},
		}, []string{"signature"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "run.signature_valid") {
		t.Fatalf("findings=%v", findings)
	}
}
