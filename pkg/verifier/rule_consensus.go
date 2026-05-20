package verifier

import (
	"fmt"
	"sort"
)

func evaluateConsensus(r rule, atts []attestation) map[string]interface{} {
	spec := r.Spec
	claim, _ := spec["claim"].(string)
	expectedValue := spec["expected_value"]
	sourcesRaw, _ := spec["sources"].([]interface{})
	threshold, _ := spec["threshold"].(map[string]interface{})

	if claim == "" {
		return finding(r, "inconclusive", "inconclusive.consensus.claim_missing",
			"consensus: missing claim", nil, nil)
	}

	sources := make([]map[string]interface{}, 0, len(sourcesRaw))
	for _, s := range sourcesRaw {
		if m, ok := s.(map[string]interface{}); ok {
			sources = append(sources, m)
		}
	}

	// Build set of allowed source identifiers from the rule.
	allowedSources := map[string]struct{}{}
	for _, s := range sources {
		if sid, ok := s["source_id"].(string); ok && sid != "" {
			allowedSources[sid] = struct{}{}
		}
		if action, ok := s["action"].(string); ok && action != "" {
			allowedSources[action] = struct{}{}
		}
	}

	matchedAtts := make([]attestation, 0)
	for _, a := range atts {
		if a.Claim != claim {
			continue
		}
		if len(allowedSources) > 0 {
			if _, ok := allowedSources[a.SourceID]; !ok {
				continue
			}
		}
		matchedAtts = append(matchedAtts, a)
	}

	if len(matchedAtts) == 0 {
		return finding(r, "fail", "fail.consensus.insufficient",
			fmt.Sprintf("consensus: no attestations found for claim %q", claim), nil, nil)
	}

	// Count agreements by grouping matched attestations by ClaimValue.
	// When expectedValue is set, count matches against it.
	// When nil, count the largest-value group as the agreeing set.
	agreeCount := 0
	var evidenceIDs []string
	if expectedValue != nil {
		for _, a := range matchedAtts {
			if valuesEqual(a.ClaimValue, expectedValue) {
				agreeCount++
				evidenceIDs = append(evidenceIDs, a.AttestationID)
			}
		}
	} else {
		groups := map[string][]string{}
		for _, a := range matchedAtts {
			key := canonicalClaimValueKey(a.ClaimValue)
			groups[key] = append(groups[key], a.AttestationID)
		}
		keys := make([]string, 0, len(groups))
		for k := range groups {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		maxKey := ""
		maxCount := 0
		for _, k := range keys {
			ids := groups[k]
			if len(ids) > maxCount || (len(ids) == maxCount && (maxKey == "" || k < maxKey)) {
				maxCount = len(ids)
				maxKey = k
			}
		}
		agreeCount = maxCount
		evidenceIDs = groups[maxKey]
	}

	// Validate threshold contains exactly one supported operator.
	if len(threshold) == 0 {
		return finding(r, "fail", "fail.consensus.threshold_unmet",
			"consensus: threshold is required", nil, nil)
	}
	supported := 0
	for k := range threshold {
		switch k {
		case "unanimous", "majority", "agree_at_least":
			supported++
		default:
			return finding(r, "fail", "fail.consensus.insufficient",
				fmt.Sprintf("consensus: unknown threshold key %q", k), nil, nil)
		}
	}
	if supported != 1 {
		return finding(r, "fail", "fail.consensus.insufficient",
			fmt.Sprintf("consensus: threshold must contain exactly one supported operator, got %d", supported), nil, nil)
	}

	// Evaluate threshold
	thresholdMet := false
	evaluated := false
	if unanimous, ok := threshold["unanimous"].(bool); ok {
		evaluated = true
		if unanimous {
			thresholdMet = agreeCount == len(matchedAtts) && len(matchedAtts) > 0
			if !thresholdMet {
				return finding(r, "fail", "fail.consensus.disagreement",
					fmt.Sprintf("consensus.disagreement: unanimous required, %d/%d agree", agreeCount, len(matchedAtts)),
					nil, evidenceIDs)
			}
		}
	} else if majority, ok := threshold["majority"].(bool); ok {
		evaluated = true
		if majority {
			thresholdMet = agreeCount > len(matchedAtts)/2
			if !thresholdMet {
				return finding(r, "fail", "fail.consensus.disagreement",
					fmt.Sprintf("consensus.disagreement: majority required, %d/%d agree", agreeCount, len(matchedAtts)),
					nil, evidenceIDs)
			}
		}
	} else if agreeAtLeast, ok := threshold["agree_at_least"]; ok {
		evaluated = true
		min, err := validateAgreeAtLeast(agreeAtLeast)
		if err != nil {
			return finding(r, "fail", "fail.consensus.insufficient",
				fmt.Sprintf("consensus: invalid agree_at_least: %v", err), nil, nil)
		}
		thresholdMet = agreeCount >= min
		if !thresholdMet {
			return finding(r, "fail", "fail.consensus.disagreement",
				fmt.Sprintf("consensus.disagreement: agree_at_least %d required, %d agree", min, agreeCount),
				nil, evidenceIDs)
		}
	}

	if !evaluated {
		return finding(r, "fail", "fail.consensus.insufficient",
			fmt.Sprintf("consensus: invalid or unevaluated threshold (keys: %+v)", threshold), nil, nil)
	}
	if !thresholdMet {
		return finding(r, "fail", "fail.consensus.threshold_unmet",
			"consensus: threshold value did not activate the rule", nil, nil)
	}

	return finding(r, "pass", "pass.consensus.threshold_met",
		fmt.Sprintf("consensus: %d/%d attestations agree on claim %q", agreeCount, len(matchedAtts), claim),
		nil, evidenceIDs)
}
