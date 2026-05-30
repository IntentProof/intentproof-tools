package bundle

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/intentproof/intentproof-tools/pkg/buildinfo"
	"github.com/intentproof/intentproof-tools/pkg/policysig"
)

// VerificationProfile records the tuple used to build and verify a bundle.
type VerificationProfile struct {
	SpecVersion     string   `json:"spec_version"`
	VerifierVersion string   `json:"verifier_version"`
	PolicyVersions  []string `json:"policy_versions"`
	ExportProfile   string   `json:"export_profile"`
	FlowSnapshotID  string   `json:"flow_snapshot_id"`
	RunID           string   `json:"run_id"`
}

func deriveVerificationProfile(opts CreateOptions) (*VerificationProfile, error) {
	if opts.VerificationProfile != nil {
		return opts.VerificationProfile, nil
	}

	specVersion := strings.TrimSpace(opts.SpecVersion)
	if specVersion == "" {
		specVersion = strings.TrimSpace(os.Getenv("INTENTPROOF_SPEC_REF"))
	}
	if specVersion == "" {
		specVersion = "unknown"
	}

	exportProfile := strings.TrimSpace(opts.ExportProfile)
	if exportProfile == "" {
		exportProfile = "full"
	}

	flowSnapshotID := strings.TrimSpace(opts.FlowSnapshotID)
	if flowSnapshotID == "" {
		flowSnapshotID = strings.TrimSpace(opts.FlowID)
	}

	runID := strings.TrimSpace(opts.RunID)
	if runID == "" && len(opts.RunJSON) > 0 {
		var run map[string]any
		if err := json.Unmarshal(opts.RunJSON, &run); err != nil {
			return nil, fmt.Errorf("decode run.json for profile: %w", err)
		}
		runID, _ = run["run_id"].(string)
	}
	if flowSnapshotID == "" && len(opts.RunJSON) > 0 {
		var run map[string]any
		if err := json.Unmarshal(opts.RunJSON, &run); err == nil {
			if fid, ok := run["flow_id"].(string); ok && strings.TrimSpace(fid) != "" {
				flowSnapshotID = fid
			}
		}
	}

	policyVersions, err := policyVersionsFromJSON(opts.PolicyJSON)
	if err != nil {
		return nil, err
	}

	verifierVersion := strings.TrimSpace(opts.VerifierVersion)
	if verifierVersion == "" {
		verifierVersion = strings.TrimSpace(buildinfo.Version)
	}
	if verifierVersion == "" {
		verifierVersion = "dev"
	}

	return &VerificationProfile{
		SpecVersion:     specVersion,
		VerifierVersion: verifierVersion,
		PolicyVersions:  policyVersions,
		ExportProfile:   exportProfile,
		FlowSnapshotID:  flowSnapshotID,
		RunID:           runID,
	}, nil
}

func policyVersionsFromJSON(raw []byte) ([]string, error) {
	raw = bytesTrimSpace(raw)
	if len(raw) == 0 {
		return nil, nil
	}
	var policy map[string]any
	if err := json.Unmarshal(raw, &policy); err != nil {
		return nil, fmt.Errorf("decode policy.json for profile: %w", err)
	}
	fp, err := policysig.ComputeFingerprint(policy)
	if err != nil {
		return nil, fmt.Errorf("policy fingerprint for profile: %w", err)
	}
	if strings.TrimSpace(fp) == "" {
		return nil, nil
	}
	return []string{fp}, nil
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

func validateVerificationProfile(m *Manifest, b *Bundle) (*VerifyResult, bool) {
	if m.VerificationProfile == nil {
		return &VerifyResult{
			Status:   "fail",
			Reason:   "bundle.verification_profile_missing",
			Findings: []string{"verification_profile.missing"},
		}, true
	}
	p := m.VerificationProfile
	findings := []string{"verification_profile.present"}

	if strings.TrimSpace(p.VerifierVersion) == "" {
		findings = append(findings, "verification_profile.verifier_version_missing")
		return &VerifyResult{
			Status:   "fail",
			Reason:   "bundle.verification_profile_invalid",
			Findings: findings,
		}, true
	}
	if !isSupportedVerifierVersion(p.VerifierVersion) {
		findings = append(findings, "verification_profile.verifier_version_unsupported")
		return &VerifyResult{
			Status:   "fail",
			Reason:   "bundle.verification_profile_unsupported",
			Findings: findings,
		}, true
	}
	findings = append(findings, "verification_profile.verifier_version_supported")

	if b.Run != nil && strings.TrimSpace(p.RunID) != "" {
		runID, _ := b.Run["run_id"].(string)
		if strings.TrimSpace(runID) != "" && runID != p.RunID {
			findings = append(findings, "verification_profile.run_id_mismatch")
			return &VerifyResult{
				Status:   "fail",
				Reason:   "bundle.verification_profile_invalid",
				Findings: findings,
			}, true
		}
	}
	findings = append(findings, "verification_profile.run_id_valid")
	return &VerifyResult{Findings: findings}, false
}

func isSupportedVerifierVersion(version string) bool {
	version = strings.TrimSpace(version)
	for _, allowed := range supportedVerifierVersions() {
		if version == allowed {
			return true
		}
	}
	return false
}

func supportedVerifierVersions() []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, candidate := range []string{
		strings.TrimSpace(buildinfo.Version),
		"dev",
	} {
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out
}
