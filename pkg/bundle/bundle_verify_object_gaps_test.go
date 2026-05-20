package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestVerifySignedMapUnsupportedAlgorithm(t *testing.T) {
	doc := map[string]interface{}{
		"event_id": "e1",
		"signature": map[string]interface{}{
			"alg": "rsa", "key_id": "k1", "value": "00",
		},
	}
	findings, err := verifySignedMap(&Bundle{PublicKeys: map[string][]byte{"k1": {1}}}, nil,
		"event", "signature", doc, []string{"signature"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "event.signature_unsupported_alg") {
		t.Fatalf("findings=%v", findings)
	}
}

func TestVerifySignedMapInvalidPublicKeyMaterial(t *testing.T) {
	doc := map[string]interface{}{
		"event_id": "e1",
		"signature": map[string]interface{}{
			"alg": "ed25519", "key_id": "k1",
			"value": hex.EncodeToString(make([]byte, ed25519.SignatureSize)),
		},
	}
	findings, err := verifySignedMap(&Bundle{PublicKeys: map[string][]byte{"k1": []byte("short")}}, nil,
		"event", "signature", doc, []string{"signature"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "event.signature_key_unavailable") {
		t.Fatalf("findings=%v", findings)
	}
}

func TestVerifyObjectSignaturesSignedEventAndAttestation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ev := map[string]interface{}{"event_id": "e1", "action": "pay"}
	evPayload, err := canonicalSignedMap(ev, []string{"signature"})
	if err != nil {
		t.Fatal(err)
	}
	evSig := ed25519.Sign(priv, sha256sum(evPayload))
	ev["signature"] = map[string]interface{}{
		"alg": "ed25519", "key_id": "sdk:k1",
		"value": hex.EncodeToString(evSig),
	}

	att := map[string]interface{}{"attestation_id": "a1"}
	attPayload, err := canonicalSignedMap(att, []string{"platform_signature"})
	if err != nil {
		t.Fatal(err)
	}
	attSig := ed25519.Sign(priv, sha256sum(attPayload))
	att["platform_signature"] = map[string]interface{}{
		"alg": "ed25519", "key_id": "plat:k1",
		"value": hex.EncodeToString(attSig),
	}

	b := &Bundle{
		PublicKeys: map[string][]byte{
			"sdk:k1":  pub,
			"plat:k1": pub,
		},
		Events:       []map[string]interface{}{ev},
		Attestations: []map[string]interface{}{att},
	}
	findings, err := verifyObjectSignatures(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "event.signature_valid") || !hasFinding(findings, "attestation.signature_valid") {
		t.Fatalf("findings=%v", findings)
	}
}

func TestIsEd25519HexSignatureRejectsBadLengthAndChars(t *testing.T) {
	if isEd25519HexSignature("abc") {
		t.Fatal("expected false for short value")
	}
	if isEd25519HexSignature(hex.EncodeToString(make([]byte, ed25519.SignatureSize))+"g") {
		t.Fatal("expected false for invalid hex char")
	}
}

func TestDecodeSignatureValueUsesBase64Fallback(t *testing.T) {
	raw := make([]byte, ed25519.SignatureSize)
	sig, err := decodeSignatureValue(hex.EncodeToString(raw))
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatalf("hex sig len=%d err=%v", len(sig), err)
	}
}
