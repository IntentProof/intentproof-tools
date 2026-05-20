package verifier

import "fmt"

func evaluateRequired(r rule, events []event) map[string]interface{} {
	spec := r.Spec
	action, _ := spec["action"].(string)
	where, _ := spec["where"].(map[string]interface{})

	matched := filterEvents(events, action, where)
	count := len(matched)

	minVal := 0
	if v, ok := spec["min"]; ok {
		minVal = intFromInterface(v)
	}
	maxVal := -1
	if v, ok := spec["max"]; ok {
		maxVal = intFromInterface(v)
	}

	if count < minVal {
		reason := "fail.required.under_min"
		summary := fmt.Sprintf("required action %q occurred %d time(s), minimum is %d", action, count, minVal)
		if count == 0 {
			reason = "fail.required.missing"
			summary = fmt.Sprintf("required action %q did not occur (minimum is %d)", action, minVal)
		}
		return finding(r, "fail", reason, summary, eventIDs(matched), nil)
	}
	if maxVal >= 0 && count > maxVal {
		return finding(r, "fail", "fail.required.over_max",
			fmt.Sprintf("required action %q occurred %d time(s), maximum is %d", action, count, maxVal),
			eventIDs(matched), nil)
	}
	return finding(r, "pass", "pass.required.satisfied",
		fmt.Sprintf("required action %q occurred %d time(s)", action, count),
		eventIDs(matched), nil)
}
