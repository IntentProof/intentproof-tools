package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestLocalEd25519SignerRoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	signer, err := NewLocalEd25519PolicySignerFromBase64(base64.StdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	if signer.Algorithm() != "ed25519" {
		t.Fatalf("expected ed25519, got %s", signer.Algorithm())
	}

	payload := []byte(`{"policy_id":"tnt_acme.p","tenant_id":"tnt_acme"}`)
	digest := sha256.Sum256(payload)

	env, err := signer.Sign(context.Background(), digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if env.Alg != "ed25519" {
		t.Fatalf("expected alg ed25519, got %s", env.Alg)
	}
	if env.KeyID == "" {
		t.Fatal("expected non-empty key_id")
	}
	if env.Value == "" {
		t.Fatal("expected non-empty value")
	}

	// Verify
	verifier := NewPolicySignatureVerifier()
	pub := signer.(*LocalEd25519PolicySigner).PublicKey()
	if err := verifier.Verify(payload, env, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestLocalEd25519SignerBadKey(t *testing.T) {
	_, err := NewLocalEd25519PolicySignerFromBase64("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestVerifierBadAlgorithm(t *testing.T) {
	verifier := NewPolicySignatureVerifier()
	env := &SignatureEnvelope{Alg: "rsa-4096", Value: "Zm9v"}
	if err := verifier.Verify([]byte("x"), env, []byte("pub")); err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestVerifierBadSignatureValue(t *testing.T) {
	verifier := NewPolicySignatureVerifier()
	env := &SignatureEnvelope{Alg: "ed25519", Value: "!!!bad-base64"}
	if err := verifier.Verify([]byte("x"), env, []byte("pub")); err == nil {
		t.Fatal("expected error for bad base64 signature")
	}
}

func TestNewPolicySignerFromEnvNone(t *testing.T) {
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "")
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", "")
	signer, err := NewPolicySignerFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signer != nil {
		t.Fatal("expected nil signer when no env is set")
	}
}

func TestNewPolicySignerFromEnvLocal(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "")
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", base64.StdEncoding.EncodeToString(priv))
	signer, err := NewPolicySignerFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signer == nil {
		t.Fatal("expected local signer")
	}
	if signer.Algorithm() != "ed25519" {
		t.Fatalf("expected ed25519, got %s", signer.Algorithm())
	}
}

func TestParseRFC3339OrNow(t *testing.T) {
	ts, err := ParseRFC3339OrNow("2026-05-12T10:00:00Z")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ts.Year() != 2026 {
		t.Fatalf("expected 2026, got %d", ts.Year())
	}

	ts2, err := ParseRFC3339OrNow("")
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if ts2.IsZero() {
		t.Fatal("expected non-zero time for empty string")
	}
}

func TestLocalEd25519SignerFromBase64(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := NewLocalEd25519PolicySignerFromBase64(base64.StdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	if signer == nil {
		t.Fatal("expected signer")
	}
}

func TestExtractSignatureEnvelope(t *testing.T) {
	body := map[string]any{
		"signature": map[string]any{
			"alg":    "ed25519",
			"key_id": "k1",
			"value":  "c2ln",
		},
	}
	env, err := ExtractSignatureEnvelope(body)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if env.Alg != "ed25519" || env.KeyID != "k1" || env.Value != "c2ln" {
		t.Fatalf("unexpected envelope: %+v", env)
	}
}

func TestExtractSignatureEnvelopeMissing(t *testing.T) {
	_, err := ExtractSignatureEnvelope(map[string]any{})
	if err == nil {
		t.Fatal("expected error for missing signature")
	}
}

func TestECDSAP256VerifyDERSignature(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	payload := []byte("test-payload")
	digest := sha256.Sum256(payload)

	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	der, err := asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})
	if err != nil {
		t.Fatalf("marshal DER: %v", err)
	}

	env := &SignatureEnvelope{
		Alg:   "ecdsa-p256",
		KeyID: "test:k1",
		Value: base64.StdEncoding.EncodeToString(der),
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}

	verifier := NewPolicySignatureVerifier()
	if err := verifier.Verify(payload, env, pubDER); err != nil {
		t.Fatalf("verify DER sig: %v", err)
	}
}

func TestECDSAP256VerifyRawSignature(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	payload := []byte("test-payload")
	digest := sha256.Sum256(payload)

	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	pointLen := 32
	raw := make([]byte, 2*pointLen)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(raw[pointLen-len(rBytes):], rBytes)
	copy(raw[2*pointLen-len(sBytes):], sBytes)

	env := &SignatureEnvelope{
		Alg:   "ecdsa-p256",
		KeyID: "test:k1",
		Value: base64.StdEncoding.EncodeToString(raw),
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}

	verifier := NewPolicySignatureVerifier()
	if err := verifier.Verify(payload, env, pubDER); err != nil {
		t.Fatalf("verify raw sig: %v", err)
	}
}

func TestVerifyEd25519MultiFormatPublicKeys(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	payload := []byte("test")
	digest := sha256.Sum256(payload)
	sig := ed25519.Sign(priv, digest[:])

	env := &SignatureEnvelope{
		Alg:   "ed25519",
		KeyID: "k1",
		Value: base64.StdEncoding.EncodeToString(sig),
	}
	verifier := NewPolicySignatureVerifier()

	// 1. Raw 32-byte key.
	if err := verifier.Verify(payload, env, pub); err != nil {
		t.Fatalf("raw key verify: %v", err)
	}

	// 2. Base64-wrapped raw key.
	b64pub := base64.StdEncoding.EncodeToString(pub)
	if err := verifier.Verify(payload, env, []byte(b64pub)); err != nil {
		t.Fatalf("base64 raw key verify: %v", err)
	}

	// 3. OpenSSH authorized-key format.
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh new public key: %v", err)
	}
	openssh := ssh.MarshalAuthorizedKey(sshPub)
	if err := verifier.Verify(payload, env, openssh); err != nil {
		t.Fatalf("openssh key verify: %v", err)
	}

	// 4. PKIX/DER format.
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("pkix marshal: %v", err)
	}
	if err := verifier.Verify(payload, env, pkix); err != nil {
		t.Fatalf("pkix key verify: %v", err)
	}

	// 5. Base64-wrapped PKIX/DER (decoded inside parseEd25519PublicKey).
	b64pkix := base64.StdEncoding.EncodeToString(pkix)
	if err := verifier.Verify(payload, env, []byte(b64pkix)); err != nil {
		t.Fatalf("base64 pkix key verify: %v", err)
	}

	// 6. PEM-wrapped PKIX/DER format.
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix})
	if err := verifier.Verify(payload, env, pemKey); err != nil {
		t.Fatalf("pem pkix key verify: %v", err)
	}
}

func sha256Sum(data []byte) []byte {
	d := sha256.Sum256(data)
	return d[:]
}
