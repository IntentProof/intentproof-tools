package verifier

import "fmt"

func evaluateClaimMatch(r rule, atts []attestation) map[string]interface{} {
	spec := r.Spec
	claim, _ := spec["claim"].(string)
	expectedValue := spec["expected_value"]
	sourceID, _ := spec["source_id"].(string)

	if claim == "" {
		return finding(r, "inconclusive", "inconclusive.claim_match.claim_missing",
			"claim_match: claim is required", nil, nil)
	}
	if expectedValue == nil {
		return finding(r, "inconclusive", "inconclusive.claim_match.expected_missing",
			"claim_match: expected_value is required", nil, nil)
	}

	matched := filterAttestations(atts, claim, sourceID)
	if len(matched) == 0 {
		return finding(r, "inconclusive", "inconclusive.claim_match.claim_missing",
			fmt.Sprintf("claim_match: no attestations found for claim %q", claim), nil, nil)
	}

	var evidence []string
	failCount := 0
	for _, a := range matched {
		evidence = append(evidence, a.AttestationID)
		if !valuesEqual(a.ClaimValue, expectedValue) {
			failCount++
		}
	}

	if failCount > 0 {
		return finding(r, "fail", "fail.claim_match.mismatch",
			fmt.Sprintf("claim_match: %d/%d attestations do not match expected value for claim %q", failCount, len(matched), claim),
			nil, evidence)
	}
	return finding(r, "pass", "pass.claim_match.matched",
		fmt.Sprintf("claim_match: all %d attestations match expected value for claim %q", len(matched), claim),
		nil, evidence)
}
