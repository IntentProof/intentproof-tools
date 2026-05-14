package policysig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/crypto"
)

func TestCanonicalizePolicy_Hash(t *testing.T) {
	policy := map[string]any{
		"schema":         "intentproof.policy.v1",
		"policy_id":      "tnt.test",
		"policy_version": 1,
		"tenant_id":      "tnt",
		"spec_version":   "1.0.0",
		"scope":          map[string]any{"any_event_action_in": []string{"a"}},
		"rules": []any{
			map[string]any{
				"id":       "r1",
				"category": "required",
				"severity": "high",
				"spec":     map[string]any{"action": "a"},
			},
		},
	}
	canonical, err := canonicalizePolicy(policy)
	if err != nil {
		t.Fatalf("canonicalizePolicy: %v", err)
	}
	wantHash := "7ffa54b2f15b9ab936a94eb3926a79bde8f66b0a81d0fee69b6c9d2c6a2fb07b"
	gotHash := hex.EncodeToString(sha256Hash(canonical))
	if gotHash != wantHash {
		t.Fatalf("canonical hash mismatch: want %s, got %s", wantHash, gotHash)
	}
}

func sha256Hash(b []byte) []byte {
	d := sha256.Sum256(b)
	return d[:]
}

func TestComputeFingerprint_Deterministic(t *testing.T) {
	policy := map[string]any{
		"schema":      "intentproof.policy.v1",
		"policy_id":   "tnt.test",
		"policy_version": 1,
		"tenant_id":   "tnt",
		"spec_version": "1.0.0",
		"scope":       map[string]any{"any_event_action_in": []string{"a"}},
		"rules":       []any{map[string]any{"id": "r1", "category": "required", "severity": "high", "spec": map[string]any{"action": "a"}}},
	}

	fp1, err := ComputeFingerprint(policy)
	if err != nil {
		t.Fatalf("first fingerprint: %v", err)
	}
	fp2, err := ComputeFingerprint(policy)
	if err != nil {
		t.Fatalf("second fingerprint: %v", err)
	}
	if fp1 != fp2 {
		t.Fatalf("fingerprints not deterministic: %q vs %q", fp1, fp2)
	}
	if fp1 == "" || fp1 == "sha256:" {
		t.Fatal("fingerprint is empty")
	}
}

func TestComputeFingerprint_ExcludesSigningFields(t *testing.T) {
	base := map[string]any{
		"schema":      "intentproof.policy.v1",
		"policy_id":   "tnt.test",
		"policy_version": 1,
		"tenant_id":   "tnt",
		"spec_version": "1.0.0",
		"scope":       map[string]any{"any_event_action_in": []string{"a"}},
		"rules":       []any{map[string]any{"id": "r1", "category": "required", "severity": "high", "spec": map[string]any{"action": "a"}}},
	}

	fp1, err := ComputeFingerprint(base)
	if err != nil {
		t.Fatalf("first fingerprint: %v", err)
	}

	base["policy_fingerprint"] = "sha256:0000"
	base["signed_at"] = "2026-01-01T00:00:00Z"
	base["signature"] = map[string]any{"alg": "ed25519", "key_id": "k1", "value": "base64"}

	fp2, err := ComputeFingerprint(base)
	if err != nil {
		t.Fatalf("second fingerprint: %v", err)
	}
	if fp1 != fp2 {
		t.Fatalf("fingerprint changed after adding signing fields: %q vs %q", fp1, fp2)
	}
}

func TestVerifyPolicySignature(t *testing.T) {
	// Generate a keypair for the test.
	signer, err := crypto.NewLocalEd25519PolicySigner()
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	localSigner, ok := signer.(*crypto.LocalEd25519PolicySigner)
	if !ok {
		t.Fatalf("signer is not *crypto.LocalEd25519PolicySigner, got %T", signer)
	}

	policy := map[string]any{
		"schema":      "intentproof.policy.v1",
		"policy_id":   "tnt.test",
		"policy_version": 1,
		"tenant_id":   "tnt",
		"spec_version": "1.0.0",
		"scope":       map[string]any{"any_event_action_in": []string{"a"}},
		"rules":       []any{map[string]any{"id": "r1", "category": "required", "severity": "high", "spec": map[string]any{"action": "a"}}},
	}

	payload, err := BuildPolicySignPayload(policy)
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}

	digest := sha256.Sum256(payload)
	ctx := context.Background()
	env, err := signer.Sign(ctx, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	pub := localSigner.PublicKey()
	if err := VerifyPolicySignature(policy, env, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyPolicySignature_Forged(t *testing.T) {
	signer, err := crypto.NewLocalEd25519PolicySigner()
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	localSigner, ok := signer.(*crypto.LocalEd25519PolicySigner)
	if !ok {
		t.Fatalf("signer is not *crypto.LocalEd25519PolicySigner, got %T", signer)
	}

	policy := map[string]any{
		"schema":      "intentproof.policy.v1",
		"policy_id":   "tnt.test",
		"policy_version": 1,
		"tenant_id":   "tnt",
		"spec_version": "1.0.0",
		"scope":       map[string]any{"any_event_action_in": []string{"a"}},
		"rules":       []any{map[string]any{"id": "r1", "category": "required", "severity": "high", "spec": map[string]any{"action": "a"}}},
	}

	ctx := context.Background()
	payload, err := BuildPolicySignPayload(policy)
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}
	digest := sha256.Sum256(payload)
	env, err := signer.Sign(ctx, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Tamper with the policy value.
	policy["policy_id"] = "tnt.tampered"
	if err := VerifyPolicySignature(policy, env, localSigner.PublicKey()); err == nil {
		t.Fatal("expected verification failure for forged policy")
	}
}

func TestExtractSignatureEnvelope(t *testing.T) {
	body := map[string]any{
		"signature": map[string]any{"alg": "ed25519", "key_id": "k1", "value": "base64"},
	}
	env, err := ExtractSignatureEnvelope(body)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if env.Alg != "ed25519" || env.KeyID != "k1" || env.Value != "base64" {
		t.Fatalf("unexpected envelope: %+v", env)
	}
}

func TestExtractSignatureEnvelope_Missing(t *testing.T) {
	body := map[string]any{}
	_, err := ExtractSignatureEnvelope(body)
	if err == nil {
		t.Fatal("expected error for missing signature")
	}
}
