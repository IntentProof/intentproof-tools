package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"
)

func TestVerifyUnsupportedAlgorithm(t *testing.T) {
	env := &SignatureEnvelope{Alg: "rsa-v1", Value: base64.StdEncoding.EncodeToString([]byte{1})}
	if err := NewPolicySignatureVerifier().Verify([]byte("x"), env, []byte{1}); err == nil {
		t.Fatal("expected unsupported algorithm")
	}
}

func TestVerifyNilEnvelope(t *testing.T) {
	if err := NewPolicySignatureVerifier().Verify([]byte("x"), nil, []byte{1}); err == nil {
		t.Fatal("expected nil envelope error")
	}
}

func TestVerifyECDSAP384(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("policy-bytes")
	digest := DigestSHA256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	env := &SignatureEnvelope{
		Alg:   "ecdsa-p384",
		Value: base64.StdEncoding.EncodeToString(der),
	}
	if err := NewPolicySignatureVerifier().Verify(payload, env, pubDER); err != nil {
		t.Fatal(err)
	}
}

func TestParseEd25519PublicKeyBase64Wrapped(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	b64 := base64.StdEncoding.EncodeToString(pub)
	got, err := ParseEd25519PublicKey([]byte(b64))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != ed25519.PublicKeySize {
		t.Fatal("size")
	}
}

func TestParseECDSAPublicKeySEC1Uncompressed(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	curve := elliptic.P256()
	x, y := priv.PublicKey.X, priv.PublicKey.Y
	coordLen := curve.Params().BitSize / 8
	pub := make([]byte, 1+2*coordLen)
	pub[0] = 0x04
	copy(pub[1:1+coordLen], x.Bytes())
	copy(pub[1+coordLen:], y.Bytes())
	got, err := parseECDSAPublicKey(curve, pub)
	if err != nil {
		t.Fatal(err)
	}
	if got.Curve != curve {
		t.Fatal("curve mismatch")
	}
}
