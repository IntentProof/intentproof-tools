package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/intentproof/intentproof-tools/pkg/policysig"
)

// Verify reads a bundle from the given reader and performs full verification.
func Verify(r io.Reader, pubkey []byte) (*VerifyResult, error) {
	b, err := Read(r)
	if err != nil {
		return nil, err
	}
	return verifyExtracted(b, pubkey)
}

// VerifyBundle runs structural verification on an extracted bundle.
func VerifyBundle(b *Bundle, pubkey []byte) (*VerifyResult, error) {
	return verifyExtracted(b, pubkey)
}

func verifyExtracted(b *Bundle, pubkey []byte) (*VerifyResult, error) {
	findings := []string{}

	if b.Manifest == nil {
		return &VerifyResult{Status: "fail", Reason: "bundle.manifest_missing", Findings: findings}, nil
	}

	if profRes, stop := validateVerificationProfile(b.Manifest, b); stop {
		profRes.Findings = append(findings, profRes.Findings...)
		return profRes, nil
	} else if len(profRes.Findings) > 0 {
		findings = append(findings, profRes.Findings...)
	}

	// 1. Verify manifest signature.
	if b.Manifest.Signature != nil && len(pubkey) > 0 {
		canonical, err := canonicalManifestJSON(b.Manifest)
		if err != nil {
			return nil, fmt.Errorf("bundle.canonicalize_failed: %w", err)
		}
		sigBytes, err := hex.DecodeString(b.Manifest.Signature.Value)
		if err != nil {
			return &VerifyResult{Status: "fail", Reason: "bundle.signature_decode_failed", Findings: findings}, nil
		}
		if !ed25519.Verify(pubkey, sha256sum(canonical), sigBytes) {
			findings = append(findings, "manifest.signature_invalid")
			return &VerifyResult{Status: "fail", Reason: "bundle.signature_invalid", Findings: findings}, nil
		}
		findings = append(findings, "manifest.signature_valid")
	}

	// 2. Verify file integrity (SHA-256 matches manifest entries).
	for _, entry := range b.Manifest.Files {
		actual, ok := b.RawFiles[entry.Path]
		if !ok {
			findings = append(findings, fmt.Sprintf("file_missing:%s", entry.Path))
			return &VerifyResult{Status: "fail", Reason: "bundle.file_missing", Findings: findings}, nil
		}
		want := strings.TrimPrefix(entry.SHA, "sha256:")
		got := sha256hex(actual)
		if want != got {
			findings = append(findings, fmt.Sprintf("file_hash_mismatch:%s", entry.Path))
			return &VerifyResult{Status: "fail", Reason: "bundle.file_hash_mismatch", Findings: findings}, nil
		}
		findings = append(findings, fmt.Sprintf("file_hash_valid:%s", entry.Path))
	}

	// 2.5 Declared policy fingerprint vs Tier-1 canonical hash (when present).
	if raw, ok := b.RawFiles["policy.json"]; ok {
		raw = bytes.TrimSpace(raw)
		if len(raw) > 0 {
			var policyMap map[string]any
			if err := json.Unmarshal(raw, &policyMap); err != nil {
				findings = append(findings, "policy.json_decode_failed")
				return nil, fmt.Errorf("bundle.policy_json_decode_failed: %w", err)
			}
			if fpVal, has := policyMap["policy_fingerprint"]; has {
				fp, ok := fpVal.(string)
				if ok && strings.TrimSpace(fp) != "" {
					computed, err := policysig.ComputeFingerprint(policyMap)
					if err != nil {
						findings = append(findings, "policy.fingerprint_error")
						return nil, fmt.Errorf("bundle.policy_fingerprint_compute: %w", err)
					}
					if fp != computed {
						findings = append(findings, "policy.fingerprint_mismatch")
						return &VerifyResult{
							Status:   "fail",
							Reason:   "bundle.policy_fingerprint_mismatch",
							Findings: findings,
						}, nil
					}
					findings = append(findings, "policy.fingerprint_valid")
				}
			}
		}
	}

	// 3. Verify event Merkle root.
	computedEventMerkle := computeItemMerkle(b.Events, "event_id")
	if b.Manifest.EventMerkle != "" && computedEventMerkle != b.Manifest.EventMerkle {
		findings = append(findings, "event_merkle_mismatch")
		return &VerifyResult{Status: "fail", Reason: "bundle.event_merkle_mismatch", Findings: findings}, nil
	}
	if b.Manifest.EventMerkle != "" {
		findings = append(findings, "event_merkle_valid")
	}

	// 4. Verify attestation Merkle root.
	computedAttMerkle := computeItemMerkle(b.Attestations, "attestation_id")
	if b.Manifest.AttMerkle != "" && computedAttMerkle != b.Manifest.AttMerkle {
		findings = append(findings, "attestation_merkle_mismatch")
		return &VerifyResult{Status: "fail", Reason: "bundle.attestation_merkle_mismatch", Findings: findings}, nil
	}
	if b.Manifest.AttMerkle != "" {
		findings = append(findings, "attestation_merkle_valid")
	}

	var sigErr error
	findings, sigErr = verifyObjectSignatures(b, findings)
	if sigErr != nil {
		return nil, sigErr
	}
	for _, f := range findings {
		if strings.HasSuffix(f, "_invalid") ||
			strings.HasSuffix(f, "_unsupported_alg") ||
			strings.HasSuffix(f, "_decode_failed") {
			return &VerifyResult{Status: "fail", Reason: "bundle.object_signature_invalid", Findings: findings}, nil
		}
	}

	findings = append(findings, "bundle.verify_pass")
	return &VerifyResult{Status: "pass", Reason: "bundle.verify_pass", Findings: findings}, nil
}

func bundleTarReader(r io.Reader) (*tar.Reader, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("bundle.read_failed: %w", err)
	}
	if isZstdFrame(data) {
		zr, err := bundleNewZstdReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("bundle.zstd_read_failed: %w", err)
		}
		decoded, err := io.ReadAll(zr)
		zr.Close()
		if err != nil {
			return nil, fmt.Errorf("bundle.zstd_decode_failed: %w", err)
		}
		return tar.NewReader(bytes.NewReader(decoded)), nil
	}
	return tar.NewReader(bytes.NewReader(data)), nil
}

func isZstdFrame(data []byte) bool {
	return len(data) >= 4 && data[0] == 0x28 && data[1] == 0xb5 && data[2] == 0x2f && data[3] == 0xfd
}
