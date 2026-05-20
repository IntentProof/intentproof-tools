package verifier

import "fmt"

func evaluateCardinality(r rule, events []event) map[string]interface{} {
	spec := r.Spec
	action, _ := spec["action"].(string)
	where, _ := spec["where"].(map[string]interface{})

	matched := filterEvents(events, action, where)
	count := len(matched)

	if exactly, ok := spec["exactly"]; ok {
		exactVal := intFromInterface(exactly)
		if count != exactVal {
			return finding(r, "fail", "fail.cardinality.not_exact",
				fmt.Sprintf("cardinality: action %q occurred %d time(s), expected exactly %d", action, count, exactVal),
				eventIDs(matched), nil)
		}
		return finding(r, "pass", "pass.cardinality.satisfied",
			fmt.Sprintf("cardinality: action %q occurred exactly %d time(s)", action, count),
			eventIDs(matched), nil)
	}

	minVal := 0
	if v, ok := spec["min"]; ok {
		minVal = intFromInterface(v)
	}
	maxVal := -1
	if v, ok := spec["max"]; ok {
		maxVal = intFromInterface(v)
	}

	if count < minVal {
		return finding(r, "fail", "fail.cardinality.under_min",
			fmt.Sprintf("cardinality: action %q occurred %d time(s), minimum is %d", action, count, minVal),
			eventIDs(matched), nil)
	}
	if maxVal >= 0 && count > maxVal {
		return finding(r, "fail", "fail.cardinality.over_max",
			fmt.Sprintf("cardinality: action %q occurred %d time(s), maximum is %d", action, count, maxVal),
			eventIDs(matched), nil)
	}
	return finding(r, "pass", "pass.cardinality.satisfied",
		fmt.Sprintf("cardinality: action %q occurred %d time(s)", action, count),
		eventIDs(matched), nil)
}
