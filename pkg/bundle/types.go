package bundle

import "github.com/klauspost/compress/zstd"

// Package bundle implements creation and verification of IntentProof .proof.tar.zst
// bundles. A bundle is a tamper-evident archive containing a flow, its events,
// attestations, policy, run, and certificate, plus a signed manifest that binds
// them together via Merkle roots.

// bundleNewZstdWriter and bundleNewZstdReader are overridden in tests.
var (
	bundleNewZstdWriter = zstd.NewWriter
	bundleNewZstdReader = zstd.NewReader
)

// Manifest is the canonical bundle manifest.
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
