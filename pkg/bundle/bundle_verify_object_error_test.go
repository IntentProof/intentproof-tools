package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestVerifyObjectSignaturesAttestationCanonicalizeError(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := map[string]interface{}{"attestation_id": "a1"}
	payload, err := canonicalSignedMap(att, []string{"platform_signature"})
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, sha256sum(payload))
	att["platform_signature"] = map[string]interface{}{
		"alg": "ed25519", "key_id": "k1",
		"value": hex.EncodeToString(sig),
	}
	att["bad"] = make(chan int)
	b := &Bundle{
		PublicKeys:   map[string][]byte{"k1": pub},
		Attestations: []map[string]interface{}{att},
	}
	_, err = verifyObjectSignatures(b, nil)
	if err == nil {
		t.Fatal("expected canonicalize error from attestation branch")
	}
}

func TestVerifyObjectSignaturesCertificateCanonicalizeError(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := map[string]interface{}{"certificate_id": "c1"}
	payload, err := canonicalSignedMap(cert, []string{"signature"})
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, sha256sum(payload))
	cert["signature"] = map[string]interface{}{
		"alg": "ed25519", "key_id": "k1",
		"value": hex.EncodeToString(sig),
	}
	cert["bad"] = make(chan int)
	b := &Bundle{
		PublicKeys:  map[string][]byte{"k1": pub},
		Certificate: cert,
	}
	_, err = verifyObjectSignatures(b, nil)
	if err == nil {
		t.Fatal("expected canonicalize error from certificate branch")
	}
}
