package policysig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/crypto"
)

func TestComputeFingerprintAndVerifyRoundTrip(t *testing.T) {
	policy := map[string]any{
		"policy_id":      "tnt.demo",
		"tenant_id":      "tnt",
		"policy_version": 1,
		"rules":          []any{},
	}
	fp, err := ComputeFingerprint(policy)
	if err != nil || fp == "" {
		t.Fatalf("fp=%s err=%v", fp, err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := crypto.NewLocalEd25519PolicySignerFromBase64(
		base64.StdEncoding.EncodeToString(priv),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := BuildPolicySignPayload(policy)
	if err != nil {
		t.Fatal(err)
	}
	env, err := signer.Sign(nil, crypto.DigestSHA256(payload))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPolicySignature(policy, env, signer.(*crypto.LocalEd25519PolicySigner).PublicKey()); err != nil {
		t.Fatal(err)
	}
}

func TestExtractSignatureEnvelopeErrors(t *testing.T) {
	if _, err := ExtractSignatureEnvelope(map[string]any{}); err == nil {
		t.Fatal("expected missing signature")
	}
	if _, err := ExtractSignatureEnvelope(map[string]any{
		"signature": "not-an-object",
	}); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestCanonicalizePolicyRejectsNonObject(t *testing.T) {
	if _, err := canonicalizePolicy([]int{1}); err == nil {
		t.Fatal("expected error")
	}
}
