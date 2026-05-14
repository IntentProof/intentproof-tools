// Package policysig combines policy canonicalization, fingerprinting, and
// signature verification into a single Tier-1 (Apache 2.0) surface.
package policysig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/intentproof/intentproof-tools/pkg/canon"
	"github.com/intentproof/intentproof-tools/pkg/crypto"
)

// canonicalizePolicy returns the deterministic JSON bytes for a policy object
// after removing fingerprint, signature, and signed_at fields. This is the
// shared canonicalization logic used by both ComputeFingerprint and
// BuildPolicySignPayload.
func canonicalizePolicy(policy any) ([]byte, error) {
	raw, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("marshal policy: %w", err)
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("unmarshal policy: %w", err)
	}

	delete(m, "policy_fingerprint")
	delete(m, "signature")
	delete(m, "signed_at")

	canonical, err := canon.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical: %w", err)
	}
	return canonical, nil
}

// ComputeFingerprint returns a deterministic sha256 fingerprint for a policy
// object.  It canonicalizes the JSON representation after removing the
// fingerprint, signature, and signed_at fields so that the hash is stable
// regardless of when signing occurs.
func ComputeFingerprint(policy any) (string, error) {
	canonical, err := canonicalizePolicy(policy)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// VerifyPolicySignature verifies that env is a valid signature over the
// canonical payload produced from bodyMap, using pubKey.
func VerifyPolicySignature(bodyMap map[string]any, env *crypto.SignatureEnvelope, pubKey []byte) error {
	payload, err := BuildPolicySignPayload(bodyMap)
	if err != nil {
		return fmt.Errorf("build sign payload: %w", err)
	}
	verifier := crypto.NewPolicySignatureVerifier()
	return verifier.Verify(payload, env, pubKey)
}

// BuildPolicySignPayload constructs the canonical byte slice that is signed.
// It mirrors ComputeFingerprint's exclusion list.
func BuildPolicySignPayload(canonicalPolicy any) ([]byte, error) {
	return canonicalizePolicy(canonicalPolicy)
}

// ExtractSignatureEnvelope parses a signature envelope from a raw JSON body map.
func ExtractSignatureEnvelope(bodyMap map[string]any) (*crypto.SignatureEnvelope, error) {
	rawSig, ok := bodyMap["signature"]
	if !ok || rawSig == nil {
		return nil, errors.New("signature missing")
	}
	sigBytes, err := json.Marshal(rawSig)
	if err != nil {
		return nil, fmt.Errorf("marshal signature: %w", err)
	}
	var env crypto.SignatureEnvelope
	if err := json.Unmarshal(sigBytes, &env); err != nil {
		return nil, fmt.Errorf("parse signature envelope: %w", err)
	}
	return &env, nil
}
