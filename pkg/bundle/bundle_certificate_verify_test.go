package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func TestVerifyObjectSignaturesSignedCertificate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := map[string]interface{}{
		"certificate_id": "c1",
		"schema":         "intentproof.certificate.v1",
	}
	payload, err := canonicalSignedMap(cert, []string{"signature"})
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, sha256sum(payload))
	cert["signature"] = map[string]interface{}{
		"alg": "ed25519", "key_id": "sdk:k1",
		"value": hex.EncodeToString(sig),
	}
	findings, err := verifyObjectSignatures(&Bundle{
		PublicKeys:  map[string][]byte{"sdk:k1": pub},
		Certificate: cert,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if strings.Contains(f, "_failed") || strings.Contains(f, "_invalid") {
			t.Fatalf("unexpected finding: %s", f)
		}
	}
}

func TestIsEd25519HexSignatureRejectsWrongLength(t *testing.T) {
	if isEd25519HexSignature(hex.EncodeToString(make([]byte, 8))) {
		t.Fatal("expected false for short signature")
	}
}
