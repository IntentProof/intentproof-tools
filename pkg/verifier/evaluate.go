package verifier

import "fmt"

func evaluateRule(r rule, events []event, atts []attestation) map[string]interface{} {
	switch r.Category {
	case "required":
		return evaluateRequired(r, events)
	case "forbidden":
		return evaluateForbidden(r, events)
	case "ordering":
		return evaluateOrdering(r, events)
	case "cardinality":
		return evaluateCardinality(r, events)
	case "temporal":
		return evaluateTemporal(r, events)
	case "consensus":
		return evaluateConsensus(r, atts)
	case "value_bound":
		return evaluateValueBound(r, atts)
	case "claim_match":
		return evaluateClaimMatch(r, atts)
	default:
		return finding(r, "inconclusive", "inconclusive.unknown.unsupported_rule_category",
			fmt.Sprintf("rule category not evaluated: %s", r.Category), nil, nil)
	}
}
