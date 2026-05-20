package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"
)

func TestParseECDSASignatureRawRSConcatenated(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := DigestSHA256([]byte("x"))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Fatal(err)
	}
	coordLen := 32
	raw := make([]byte, 2*coordLen)
	copy(raw[:coordLen], r.Bytes())
	copy(raw[coordLen:], s.Bytes())
	parsed, err := parseECDSASignature(elliptic.P256(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.R == nil || parsed.S == nil {
		t.Fatal("nil parts")
	}
}

func TestVerifyECDSARejectsWrongCurveKey(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	payload := []byte("policy")
	digest := DigestSHA256(payload)
	r, s, _ := ecdsa.Sign(rand.Reader, p256, digest)
	sig, _ := asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})
	env := &SignatureEnvelope{Alg: "ecdsa-p256", Value: base64.StdEncoding.EncodeToString(sig)}
	if err := NewPolicySignatureVerifier().Verify(payload, env, der); err == nil {
		t.Fatal("expected curve mismatch failure")
	}
}
