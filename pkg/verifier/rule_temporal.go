package verifier

import "fmt"

func evaluateTemporal(r rule, events []event) map[string]interface{} {
	spec := r.Spec
	fromSpec, _ := spec["from"].(map[string]interface{})
	toSpec, _ := spec["to"].(map[string]interface{})
	maxDur, _ := spec["max"].(string)

	fromAction, _ := fromSpec["action"].(string)
	toAction, _ := toSpec["action"].(string)

	fromEvents := filterEvents(events, fromAction, nil)
	toEvents := filterEvents(events, toAction, nil)

	if len(fromEvents) == 0 {
		return finding(r, "inconclusive", "inconclusive.temporal.missing_anchor",
			fmt.Sprintf("temporal: from action %q not found", fromAction), nil, nil)
	}
	if len(toEvents) == 0 {
		return finding(r, "inconclusive", "inconclusive.temporal.missing_anchor",
			fmt.Sprintf("temporal: to action %q not found", toAction), nil, nil)
	}

	fromTime := earliestCompletion(fromEvents)
	toTime := earliestCompletion(toEvents)

	if fromTime.IsZero() || toTime.IsZero() {
		return finding(r, "inconclusive", "inconclusive.temporal.missing_anchor",
			"temporal: unable to determine timestamps", nil, nil)
	}

	duration := toTime.Sub(fromTime)
	if duration < 0 {
		return finding(r, "fail", "fail.temporal.negative_interval",
			"temporal: 'to' event occurs before 'from' event", nil, nil)
	}
	maxDuration, err := parseISODuration(maxDur)
	if err != nil {
		return finding(r, "inconclusive", "inconclusive.temporal.duration_invalid",
			fmt.Sprintf("temporal: invalid max duration %q", maxDur), nil, nil)
	}

	if duration <= maxDuration {
		return finding(r, "pass", "pass.temporal.within_window",
			fmt.Sprintf("temporal: duration %v within max %v", duration, maxDuration), nil, nil)
	}
	return finding(r, "fail", "fail.temporal.exceeded_max",
		fmt.Sprintf("temporal: duration %v exceeds max %v", duration, maxDuration), nil, nil)
}
