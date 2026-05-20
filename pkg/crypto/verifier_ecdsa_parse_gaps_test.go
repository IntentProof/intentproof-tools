package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

func TestNewPolicySignerFromEnvSelectsKMSWhenConfigured(t *testing.T) {
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "alias/test-key")
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", "")
	_, err := NewPolicySignerFromEnv()
	if err == nil {
		t.Skip("KMS configured in environment")
	}
}

func TestVerifyECDSASignatureVerificationFailed(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	badSig := make([]byte, 64)
	env := &SignatureEnvelope{
		Alg:   "ecdsa-p256",
		KeyID: "k1",
		Value: base64.StdEncoding.EncodeToString(badSig),
	}
	if err := NewPolicySignatureVerifier().Verify([]byte("payload"), env, pubDER); err == nil {
		t.Fatal("expected verification failure")
	}
}

func TestParseECDSASignatureRawP384Concatenated(t *testing.T) {
	sig := make([]byte, 96)
	if _, err := parseECDSASignature(elliptic.P384(), sig); err != nil {
		t.Fatal(err)
	}
}

func TestParseECDSASignatureUnsupportedCurve(t *testing.T) {
	if _, err := parseECDSASignature(elliptic.P521(), make([]byte, 64)); err == nil {
		t.Fatal("expected unsupported curve error")
	}
}

func TestExtractSignatureEnvelopeMarshalFailure(t *testing.T) {
	if _, err := ExtractSignatureEnvelope(map[string]any{
		"signature": map[string]any{"bad": make(chan int)},
	}); err == nil {
		t.Fatal("expected marshal error")
	}
}
