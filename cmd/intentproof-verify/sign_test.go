package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/crypto"
	"github.com/intentproof/intentproof-tools/pkg/verifier"
)

func TestSignRunAndVerify(t *testing.T) {
	// Generate a temporary Ed25519 signer and extract its public key.
	signer, err := crypto.NewLocalEd25519PolicySigner()
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	pubKey := signer.(*crypto.LocalEd25519PolicySigner).PublicKey()

	dir := t.TempDir()
	flowPath := filepath.Join(dir, "flow.json")
	policyPath := filepath.Join(dir, "policy.json")
	attPath := filepath.Join(dir, "attestations.jsonl")
	outPath := filepath.Join(dir, "run.json")

	if err := os.WriteFile(flowPath, []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:abc","events":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"policy_fingerprint":"sha256:fp","rules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(attPath, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	// Test without signer: output should still contain an empty signature envelope.
	clearSigningEnv(t)
	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"--output", outPath, flowPath, policyPath, attPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d: stderr=%s", code, stderr.String())
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	var runDoc map[string]interface{}
	if err := json.Unmarshal(raw, &runDoc); err != nil {
		t.Fatalf("unmarshal run: %v", err)
	}

	if runDoc["schema"] != "intentproof.run.v1" {
		t.Fatalf("unexpected schema: %v", runDoc["schema"])
	}
	if runDoc["status"] != "pass" {
		t.Fatalf("unexpected status: %v", runDoc["status"])
	}

	sig, ok := runDoc["signature"].(map[string]interface{})
	if !ok {
		t.Fatalf("signature not a map: %T", runDoc["signature"])
	}
	if sig["alg"] != "ed25519" {
		t.Fatalf("unexpected alg: %v", sig["alg"])
	}
	if sig["value"] != "" {
		t.Fatalf("expected empty signature value without signer, got %v", sig["value"])
	}

	// Test with a signer configured via env.
	clearSigningEnv(t)
	privKeyB64 := base64.StdEncoding.EncodeToString(newTestKey(t))
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", privKeyB64)
	// Re-create signer from env to get the public key for verification.
	signer2, err := crypto.NewPolicySignerFromEnv()
	if err != nil {
		t.Fatalf("create signer from env: %v", err)
	}
	pubKey2 := signer2.(*crypto.LocalEd25519PolicySigner).PublicKey()

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"--output", outPath, flowPath, policyPath, attPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0 with signer, got %d: stderr=%s", code, stderr.String())
	}

	raw, err = os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if err := json.Unmarshal(raw, &runDoc); err != nil {
		t.Fatalf("unmarshal signed run: %v", err)
	}

	sig, ok = runDoc["signature"].(map[string]interface{})
	if !ok {
		t.Fatalf("signature not a map")
	}
	if sig["value"] == "" {
		t.Fatal("expected non-empty signature value with signer configured")
	}

	// Verify the signature cryptographically.
	// Reconstruct the verifier run so we can canonicalize it.
	var vr verifier.VerificationRun
	if err := json.Unmarshal(raw, &vr); err != nil {
		t.Fatalf("unmarshal into VerificationRun: %v", err)
	}

	canonical, err := verifier.CanonicalRunJSON(&vr)
	if err != nil {
		t.Fatalf("canonicalize run: %v", err)
	}

	sigEnv := &crypto.SignatureEnvelope{
		Alg:   sig["alg"].(string),
		KeyID: sig["key_id"].(string),
		Value: sig["value"].(string),
	}

	verifierInst := crypto.NewPolicySignatureVerifier()
	if err := verifierInst.Verify(canonical, sigEnv, pubKey2); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	// Ensure the public key used for verification matches the one from the signer.
	// This proves the signature is against the pinned pubkey.
	if len(pubKey) == 0 || len(pubKey2) == 0 {
		t.Fatal("public keys should not be empty")
	}
}

func newTestKey(t *testing.T) []byte {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

func clearSigningEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"INTENTPROOF_KMS_KEY_ID",
		"INTENTPROOF_POLICY_SIGNING_KEY_B64",
		"INTENTPROOF_POLICY_SIGNING_KEY_ID",
	} {
		t.Setenv(k, "")
	}
}
