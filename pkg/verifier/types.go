package verifier

import (
	"os"
	"time"
)

// nowFunc is swappable for deterministic tests.
var nowFunc = func() time.Time { return time.Now().UTC() }

// SetNowFuncForTest overrides the verifier clock and returns a restore
// function. It is intended for deterministic golden fixtures.
func SetNowFuncForTest(f func() time.Time) func() {
	old := nowFunc
	nowFunc = f
	return func() {
		nowFunc = old
	}
}

func init() {
	if os.Getenv("INTENTPROOF_DETERMINISTIC_TIME") == "1" {
		nowFunc = func() time.Time {
			return time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
		}
	}
}

// VerificationRun is the canonical output of policy evaluation.
type VerificationRun struct {
	Schema            string                   `json:"schema"`
	RunID             string                   `json:"run_id"`
	TenantID          string                   `json:"tenant_id"`
	FlowID            string                   `json:"flow_id"`
	FlowMerkleRoot    string                   `json:"flow_merkle_root"`
	PolicyID          string                   `json:"policy_id"`
	PolicyVersion     int                      `json:"policy_version"`
	PolicyFingerprint string                   `json:"policy_fingerprint"`
	VerifierVersion   string                   `json:"verifier_version"`
	VerifierBuildHash string                   `json:"verifier_build_hash"`
	AttestationSet    AttestationSet           `json:"attestation_set"`
	StartedAt         string                   `json:"started_at"`
	CompletedAt       string                   `json:"completed_at"`
	Status            string                   `json:"status"`
	Summary           Summary                  `json:"summary"`
	Findings          []map[string]interface{} `json:"findings"`
	RunFingerprint    string                   `json:"run_fingerprint"`
	Signature         map[string]interface{}   `json:"signature"`
}

type AttestationSet struct {
	IDs        []string `json:"ids"`
	MerkleRoot string   `json:"merkle_root"`
}

type Summary struct {
	OutcomeCounts  map[string]int `json:"outcome_counts"`
	SeverityCounts map[string]int `json:"severity_counts"`
}

// event represents an execution event within a flow.
type event struct {
	EventID     string                 `json:"event_id"`
	Action      string                 `json:"action"`
	Status      string                 `json:"status"`
	StartedAt   string                 `json:"started_at"`
	CompletedAt string                 `json:"completed_at"`
	Attributes  map[string]interface{} `json:"attributes"`
}

// policyDoc is the canonical policy as consumed by the verifier.
type policyDoc struct {
	PolicyID          string `json:"policy_id"`
	PolicyVersion     int    `json:"policy_version"`
	TenantID          string `json:"tenant_id"`
	PolicyFingerprint string `json:"policy_fingerprint"`
	Rules             []rule `json:"rules"`
}

type rule struct {
	ID       string                 `json:"id"`
	Category string                 `json:"category"`
	Severity string                 `json:"severity"`
	Spec     map[string]interface{} `json:"spec"`
}

type attestation struct {
	AttestationID string                 `json:"attestation_id"`
	SourceID      string                 `json:"source_id"`
	Claim         string                 `json:"claim"`
	ClaimValue    interface{}            `json:"claim_value"`
	Subject       map[string]interface{} `json:"subject"`
}

const verifierVersion = "1.0.0"
const verifierBuildHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
