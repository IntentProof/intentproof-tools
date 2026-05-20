package verifier

import "fmt"

func evaluateOrdering(r rule, events []event) map[string]interface{} {
	spec := r.Spec
	beforeAction, _ := spec["before"].(string)
	afterAction, _ := spec["after"].(string)

	beforeEvents := filterEvents(events, beforeAction, nil)
	afterEvents := filterEvents(events, afterAction, nil)

	if len(beforeEvents) == 0 {
		return finding(r, "inconclusive", "inconclusive.ordering.before_missing",
			fmt.Sprintf("ordering: before action %q not found", beforeAction), nil, nil)
	}
	if len(afterEvents) == 0 {
		return finding(r, "inconclusive", "inconclusive.ordering.after_missing",
			fmt.Sprintf("ordering: after action %q not found", afterAction), nil, nil)
	}

	beforeTime := earliestCompletion(beforeEvents)
	afterTime := earliestCompletion(afterEvents)

	if !beforeTime.IsZero() && !afterTime.IsZero() && beforeTime.Before(afterTime) {
		return finding(r, "pass", "pass.ordering.satisfied",
			fmt.Sprintf("ordering: %q completed before %q", beforeAction, afterAction),
			eventIDs(append(beforeEvents, afterEvents...)), nil)
	}
	return finding(r, "fail", "fail.ordering.out_of_order",
		fmt.Sprintf("ordering: %q did not complete before %q", beforeAction, afterAction),
		eventIDs(append(beforeEvents, afterEvents...)), nil)
}
