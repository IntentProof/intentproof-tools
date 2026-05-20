package verifier

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/policysig"
)

// Verify evaluates a policy against a flow and attestations.
func Verify(flowData []byte, policyData []byte, attestationsData []byte) (*VerificationRun, error) {
	started := nowFunc()

	var flow struct {
		FlowID         string  `json:"flow_id"`
		TenantID       string  `json:"tenant_id"`
		FlowMerkleRoot string  `json:"flow_merkle_root"`
		Events         []event `json:"events"`
	}
	if err := json.Unmarshal(flowData, &flow); err != nil {
		return nil, fmt.Errorf("parse flow: %w", err)
	}

	var policy policyDoc
	if err := json.Unmarshal(policyData, &policy); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	var policyRaw map[string]any
	if err := json.Unmarshal(policyData, &policyRaw); err != nil {
		return nil, fmt.Errorf("parse policy map: %w", err)
	}
	if err := validateDeclaredPolicyFingerprint(policyRaw); err != nil {
		return nil, err
	}
	if flow.TenantID != "" && policy.TenantID != "" && flow.TenantID != policy.TenantID {
		return nil, fmt.Errorf("tenant mismatch: flow tenant %q does not match policy tenant %q", flow.TenantID, policy.TenantID)
	}

	atts, err := parseAttestations(attestationsData)
	if err != nil {
		return nil, fmt.Errorf("parse attestations: %w", err)
	}

	findings := make([]map[string]interface{}, 0, len(policy.Rules))
	outcomeCounts := map[string]int{"pass": 0, "fail": 0, "inconclusive": 0}
	severityCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

	for _, r := range policy.Rules {
		finding := evaluateRule(r, flow.Events, atts)
		findings = append(findings, finding)
		outcomeCounts[finding["outcome"].(string)]++
		severityCounts[finding["severity"].(string)]++
	}

	status := "pass"
	if outcomeCounts["fail"] > 0 {
		status = "fail"
	} else if outcomeCounts["inconclusive"] > 0 {
		status = "inconclusive"
	}

	attestationIDs := make([]string, 0, len(atts))
	for _, a := range atts {
		attestationIDs = append(attestationIDs, a.AttestationID)
	}

	run := &VerificationRun{
		Schema:            "intentproof.run.v1",
		RunID:             "run_" + flow.FlowID,
		TenantID:          policy.TenantID,
		FlowID:            flow.FlowID,
		FlowMerkleRoot:    flow.FlowMerkleRoot,
		PolicyID:          policy.PolicyID,
		PolicyVersion:     policy.PolicyVersion,
		PolicyFingerprint: policy.PolicyFingerprint,
		VerifierVersion:   verifierVersion,
		VerifierBuildHash: verifierBuildHash,
		AttestationSet: AttestationSet{
			IDs:        attestationIDs,
			MerkleRoot: computeMerkleRoot(attestationIDs),
		},
		StartedAt:   started.Format(time.RFC3339),
		CompletedAt: nowFunc().Format(time.RFC3339),
		Status:      status,
		Summary: Summary{
			OutcomeCounts:  outcomeCounts,
			SeverityCounts: severityCounts,
		},
		Findings: findings,
		Signature: map[string]interface{}{
			"alg":    "ed25519",
			"key_id": "platform:k1",
			"value":  "",
		},
	}

	fingerprint, err := computeRunFingerprint(run)
	if err != nil {
		return nil, fmt.Errorf("compute run fingerprint: %w", err)
	}
	run.RunFingerprint = fingerprint

	return run, nil
}

// validateDeclaredPolicyFingerprint returns an error when policy JSON carries a
// non-empty policy_fingerprint that does not match Tier-1 canonical hashing.
// Policies with no fingerprint (common in unit tests) skip this check.
func validateDeclaredPolicyFingerprint(policy map[string]any) error {
	fpVal, ok := policy["policy_fingerprint"]
	if !ok || fpVal == nil {
		return nil
	}
	fp, ok := fpVal.(string)
	if !ok || strings.TrimSpace(fp) == "" {
		return nil
	}
	computed, err := policysig.ComputeFingerprint(policy)
	if err != nil {
		return fmt.Errorf("policy fingerprint: %w", err)
	}
	if fp != computed {
		return fmt.Errorf(
			"policy fingerprint mismatch: declared %q != computed %q",
			fp, computed,
		)
	}
	return nil
}

func parseAttestations(data []byte) ([]attestation, error) {
	if len(data) == 0 {
		return []attestation{}, nil
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	atts := make([]attestation, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var a attestation
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			return nil, fmt.Errorf("parse attestation line: %w", err)
		}
		atts = append(atts, a)
	}
	return atts, nil
}
