package verifier

import "fmt"

func evaluateForbidden(r rule, events []event) map[string]interface{} {
	spec := r.Spec
	action, _ := spec["action"].(string)
	where, _ := spec["where"].(map[string]interface{})
	after, _ := spec["after"].(string)
	wherePredecessor, _ := spec["where_predecessor"].(map[string]interface{})
	withoutPredecessor, _ := spec["without_predecessor"].(string)

	matched := filterEvents(events, action, where)

	if after != "" {
		predecessors := filterEvents(events, after, wherePredecessor)
		if len(predecessors) > 0 {
			for _, m := range matched {
				mTime := parseEventTime(m.CompletedAt)
				for _, p := range predecessors {
					pTime := parseEventTime(p.CompletedAt)
					if !mTime.IsZero() && !pTime.IsZero() && mTime.After(pTime) {
						return finding(r, "fail", "fail.forbidden.after_predecessor",
							fmt.Sprintf("forbidden action %q occurred after %q", action, after),
							[]string{m.EventID}, nil)
					}
				}
			}
		}
		return finding(r, "pass", "pass.forbidden.absent",
			fmt.Sprintf("forbidden action %q did not occur after %q", action, after), nil, nil)
	}

	if withoutPredecessor != "" {
		predecessors := filterEvents(events, withoutPredecessor, wherePredecessor)
		if len(predecessors) == 0 && len(matched) > 0 {
			return finding(r, "fail", "fail.forbidden.without_predecessor",
				fmt.Sprintf("forbidden action %q occurred without predecessor %q", action, withoutPredecessor),
				eventIDs(matched), nil)
		}
		// Ensure each matched forbidden event has at least one predecessor BEFORE it.
		var unmatched []event
		for _, m := range matched {
			mTime := parseEventTime(m.CompletedAt)
			hasEarlier := false
			for _, p := range predecessors {
				pTime := parseEventTime(p.CompletedAt)
				if !mTime.IsZero() && !pTime.IsZero() && pTime.Before(mTime) {
					hasEarlier = true
					break
				}
			}
			if !hasEarlier {
				unmatched = append(unmatched, m)
			}
		}
		if len(unmatched) > 0 {
			return finding(r, "fail", "fail.forbidden.without_predecessor",
				fmt.Sprintf("forbidden action %q occurred without earlier predecessor %q", action, withoutPredecessor),
				eventIDs(unmatched), nil)
		}
		return finding(r, "pass", "pass.forbidden.absent",
			fmt.Sprintf("forbidden action %q constraint satisfied", action), nil, nil)
	}

	if len(matched) > 0 {
		return finding(r, "fail", "fail.forbidden.present",
			fmt.Sprintf("forbidden action %q occurred %d time(s)", action, len(matched)),
			eventIDs(matched), nil)
	}
	return finding(r, "pass", "pass.forbidden.absent",
		fmt.Sprintf("forbidden action %q did not occur", action), nil, nil)
}
