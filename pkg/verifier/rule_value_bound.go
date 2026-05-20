package verifier

import "fmt"

func evaluateValueBound(r rule, atts []attestation) map[string]interface{} {
	spec := r.Spec
	claim, _ := spec["claim"].(string)
	operator, _ := spec["operator"].(string)
	sourceID, _ := spec["source_id"].(string)

	if claim == "" || operator == "" {
		return finding(r, "inconclusive", "inconclusive.value_bound.claim_missing",
			"value_bound: claim and operator are required", nil, nil)
	}

	// Validate operator is supported.
	if !isValidValueBoundOperator(operator) {
		return finding(r, "inconclusive", "inconclusive.value_bound.operator_unsupported",
			fmt.Sprintf("value_bound: unsupported operator %q", operator), nil, nil)
	}

	// Validate bound value exists and is numeric.
	boundValue, ok := toFloat64(spec["value"])
	if !ok {
		return finding(r, "inconclusive", "inconclusive.value_bound.bound_invalid",
			"value_bound: spec value must be numeric", nil, nil)
	}

	matched := filterAttestations(atts, claim, sourceID)
	if len(matched) == 0 {
		return finding(r, "inconclusive", "inconclusive.value_bound.claim_missing",
			fmt.Sprintf("value_bound: no attestations found for claim %q", claim), nil, nil)
	}

	var evidence []string
	failCount := 0
	for _, a := range matched {
		evidence = append(evidence, a.AttestationID)
		num, ok := toFloat64(a.ClaimValue)
		if !ok {
			failCount++
			continue
		}
		if !compareValueBound(num, operator, boundValue) {
			failCount++
		}
	}

	if failCount > 0 {
		return finding(r, "fail", "fail.value_bound.out_of_range",
			fmt.Sprintf("value_bound: %d/%d attestations violate %s %v for claim %q", failCount, len(matched), operator, boundValue, claim),
			nil, evidence)
	}
	return finding(r, "pass", "pass.value_bound.satisfied",
		fmt.Sprintf("value_bound: all %d attestations satisfy %s %v for claim %q", len(matched), operator, boundValue, claim),
		nil, evidence)
}

func isValidValueBoundOperator(op string) bool {
	switch op {
	case "lt", "lte", "gt", "gte", "eq", "ne":
		return true
	}
	return false
}
