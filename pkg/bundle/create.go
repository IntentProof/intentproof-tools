package bundle

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"
)

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
	CreatedAt            time.Time
	Signer               func([]byte) (*SignatureEnvelope, error)
	VerificationProfile  *VerificationProfile
	SpecVersion          string
	VerifierVersion      string
	ExportProfile        string
	FlowSnapshotID       string
	RunID                string
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
	createdAt := opts.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	manifest := &Manifest{
		Schema:      "intentproof.bundle.manifest.v1",
		BundleID:    opts.BundleID,
		CreatedAt:   createdAt.Format(time.RFC3339),
		FlowID:      opts.FlowID,
		TenantID:    opts.TenantID,
		Files:       manifestEntries,
		EventMerkle: eventMerkle,
		AttMerkle:   attMerkle,
	}
	profile, err := deriveVerificationProfile(opts)
	if err != nil {
		return fmt.Errorf("verification profile: %w", err)
	}
	manifest.VerificationProfile = profile

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
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		body := files[name]
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

	zw, err := bundleNewZstdWriter(w)
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
