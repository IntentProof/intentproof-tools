// Package bundle implements creation and verification of IntentProof .proof.tar.zst
// bundles. A bundle is a tamper-evident archive containing a flow, its events,
// attestations, policy, run, and certificate, plus a signed manifest that binds
// them together via Merkle roots.
package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/canon"
	"github.com/intentproof/intentproof-tools/pkg/merkle"
	"github.com/intentproof/intentproof-tools/pkg/policysig"
	"github.com/klauspost/compress/zstd"
)

// Manifest is the canonical bundle manifest. It is signed by the platform
// and included in the bundle as manifest.json.
type Manifest struct {
	Schema      string             `json:"schema"`
	BundleID    string             `json:"bundle_id"`
	CreatedAt   string             `json:"created_at"`
	FlowID      string             `json:"flow_id"`
	TenantID    string             `json:"tenant_id"`
	Files       []ManifestEntry    `json:"files"`
	EventMerkle string             `json:"event_merkle_root"`
	AttMerkle   string             `json:"attestation_merkle_root"`
	Signature   *SignatureEnvelope `json:"signature,omitempty"`
}

type ManifestEntry struct {
	Path string `json:"path"`
	SHA  string `json:"sha256"`
}

type SignatureEnvelope struct {
	Alg   string `json:"alg"`
	KeyID string `json:"key_id"`
	Value string `json:"value"`
}

// Bundle holds the in-memory representation of an extracted bundle.
type Bundle struct {
	Manifest       *Manifest
	Flow           map[string]interface{}
	Events         []map[string]interface{}
	Attestations   []map[string]interface{}
	Policy         map[string]interface{}
	Run            map[string]interface{}
	Certificate    map[string]interface{}
	InclusionProof []string
	PublicKeys     map[string][]byte
	RawFiles       map[string][]byte // extracted raw bytes for integrity checks
}

// VerifyResult is the output of bundle verification.
type VerifyResult struct {
	Status   string   `json:"status"` // "pass", "fail", "inconclusive"
	Reason   string   `json:"reason"`
	Findings []string `json:"findings"`
}

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

// CreateOptions holds the inputs needed to build a bundle.
type CreateOptions struct {
	BundleID          string
	FlowID            string
	TenantID          string
	FlowJSON          []byte
	EventsJSONL       []byte
	AttestationsJSONL []byte
	PolicyJSON        []byte
	RunJSON           []byte
	CertificateJSON   []byte
	InclusionProof    []byte
	PublicKeys        map[string][]byte
	Signer            func([]byte) (*SignatureEnvelope, error)
}

// Create builds a bundle and writes it to the given writer as a tar.zst stream.
func Create(w io.Writer, opts CreateOptions) error {
	files := map[string][]byte{
		"flow.json":          opts.FlowJSON,
		"events.jsonl":       opts.EventsJSONL,
		"attestations.jsonl": opts.AttestationsJSONL,
		"policy.json":        opts.PolicyJSON,
		"run.json":           opts.RunJSON,
	}
	if len(opts.CertificateJSON) > 0 {
		files["certificate.json"] = opts.CertificateJSON
	}
	if len(opts.InclusionProof) > 0 {
		files["inclusion_proof.json"] = opts.InclusionProof
	}

	// Collect public keys.
	for k, v := range opts.PublicKeys {
		files["keys/"+k+".pub"] = v
	}

	// Compute per-file SHA-256 and event/attestation Merkle roots.
	manifestEntries := make([]ManifestEntry, 0, len(files))
	for path, body := range files {
		manifestEntries = append(manifestEntries, ManifestEntry{
			Path: path,
			SHA:  "sha256:" + sha256hex(body),
		})
	}
	sort.Slice(manifestEntries, func(i, j int) bool {
		return manifestEntries[i].Path < manifestEntries[j].Path
	})

	events := parseJSONL(opts.EventsJSONL)
	atts := parseJSONL(opts.AttestationsJSONL)

	eventMerkle := computeItemMerkle(events, "event_id")
	attMerkle := computeItemMerkle(atts, "attestation_id")

	manifest := &Manifest{
		Schema:      "intentproof.bundle.manifest.v1",
		BundleID:    opts.BundleID,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		FlowID:      opts.FlowID,
		TenantID:    opts.TenantID,
		Files:       manifestEntries,
		EventMerkle: eventMerkle,
		AttMerkle:   attMerkle,
	}

	if opts.Signer != nil {
		canonical, err := canonicalManifestJSON(manifest)
		if err != nil {
			return fmt.Errorf("canonicalize manifest: %w", err)
		}
		sig, err := opts.Signer(canonical)
		if err != nil {
			return fmt.Errorf("sign manifest: %w", err)
		}
		manifest.Signature = sig
	}

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	files["manifest.json"] = manifestJSON

	// Build tar archive in memory.
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for name, body := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(body); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}

	zw, err := zstd.NewWriter(w)
	if err != nil {
		return fmt.Errorf("create zstd writer: %w", err)
	}
	if _, err := io.Copy(zw, &tarBuf); err != nil {
		_ = zw.Close()
		return fmt.Errorf("write zstd bundle: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("close zstd bundle: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

// Verify reads a bundle from the given reader and performs full verification.
func Verify(r io.Reader, pubkey []byte) (*VerifyResult, error) {
	tr, err := bundleTarReader(r)
	if err != nil {
		return nil, err
	}
	b := &Bundle{PublicKeys: map[string][]byte{}, RawFiles: map[string][]byte{}}
	findings := []string{}

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundle.tar_read_failed: %w", err)
		}
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, tr); err != nil {
			return nil, fmt.Errorf("bundle.tar_extract_failed: %w", err)
		}
		body := buf.Bytes()
		b.RawFiles[hdr.Name] = body

		switch hdr.Name {
		case "manifest.json":
			var m Manifest
			if err := json.Unmarshal(body, &m); err != nil {
				return nil, fmt.Errorf("bundle.manifest_decode_failed: %w", err)
			}
			b.Manifest = &m
		case "flow.json":
			json.Unmarshal(body, &b.Flow)
		case "events.jsonl":
			b.Events = parseJSONL(body)
		case "attestations.jsonl":
			b.Attestations = parseJSONL(body)
		case "policy.json":
			json.Unmarshal(body, &b.Policy)
		case "run.json":
			json.Unmarshal(body, &b.Run)
		case "certificate.json":
			json.Unmarshal(body, &b.Certificate)
		case "inclusion_proof.json":
			json.Unmarshal(body, &b.InclusionProof)
		default:
			if strings.HasPrefix(hdr.Name, "keys/") && strings.HasSuffix(hdr.Name, ".pub") {
				keyID := strings.TrimSuffix(strings.TrimPrefix(hdr.Name, "keys/"), ".pub")
				b.PublicKeys[keyID] = body
			}
		}
	}

	if b.Manifest == nil {
		return &VerifyResult{Status: "fail", Reason: "bundle.manifest_missing", Findings: findings}, nil
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

	findings = append(findings, "bundle.verify_pass")
	return &VerifyResult{Status: "pass", Reason: "bundle.verify_pass", Findings: findings}, nil
}

func bundleTarReader(r io.Reader) (*tar.Reader, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("bundle.read_failed: %w", err)
	}
	if isZstdFrame(data) {
		zr, err := zstd.NewReader(bytes.NewReader(data))
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func parseJSONL(data []byte) []map[string]interface{} {
	if len(data) == 0 {
		return nil
	}
	var out []map[string]interface{}
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal(line, &m); err == nil {
			out = append(out, m)
		}
	}
	return out
}

func jsonlBytes(items []map[string]interface{}) []byte {
	var buf bytes.Buffer
	for i, item := range items {
		if i > 0 {
			buf.WriteByte('\n')
		}
		b, _ := json.Marshal(item)
		buf.Write(b)
	}
	return buf.Bytes()
}

func mustMarshal(v map[string]interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func sha256hex(data []byte) string {
	return hex.EncodeToString(sha256sum(data))
}

func sha256sum(data []byte) []byte {
	d := sha256.Sum256(data)
	return d[:]
}

// canonicalManifestJSON returns deterministic JSON for signing/verifying.
func canonicalManifestJSON(m *Manifest) ([]byte, error) {
	// Copy to avoid mutating the original.
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var tmp map[string]interface{}
	if err := json.Unmarshal(raw, &tmp); err != nil {
		return nil, err
	}
	delete(tmp, "signature")
	return canon.Marshal(tmp)
}

// computeItemMerkle builds a Merkle root from a list of JSON items using the
// "idField" as the leaf data (e.g. "event_id", "attestation_id").
func computeItemMerkle(items []map[string]interface{}, idField string) string {
	ids := make([]string, len(items))
	for i, item := range items {
		v, _ := item[idField].(string)
		ids[i] = v
	}
	if len(ids) == 0 {
		return merkle.RootHex(nil)
	}
	sort.Strings(ids)
	leaves := make([][]byte, len(ids))
	for i, id := range ids {
		leaves[i] = []byte(id)
	}
	return merkle.RootHex(leaves)
}
