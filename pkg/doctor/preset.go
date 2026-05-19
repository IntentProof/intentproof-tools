package doctor

import (
	"fmt"
	"sort"
	"strings"
)

type presetRule struct {
	name        string
	referenceID string
	required    []string
}

// presetActionAliases maps canonical preset actions to common demo/app variants.
var presetActionAliases = map[string][]string{
	"ledger.refund.record":   {"ledger.entry.write"},
	"customer.notify.refund": {"customer.notify"},
}

// refundPresets matches onboarding preset labels in references/16-onboarding.md.
var refundPresets = []presetRule{
	{
		name:        "refund-basic",
		referenceID: "reference.payments.refund-basic.v1",
		required:    []string{"payments.refund.execute"},
	},
	{
		name:        "refund-with-ledger",
		referenceID: "reference.payments.refund-with-ledger.v1",
		required:    []string{"payments.refund.execute", "ledger.refund.record"},
	},
	{
		name:        "refund-with-notification",
		referenceID: "reference.payments.refund-with-notification.v1",
		required: []string{
			"payments.refund.execute",
			"ledger.refund.record",
			"customer.notify.refund",
		},
	},
}

type presetAdvice struct {
	Status  Status
	Summary string
	Hint    string
}

func advisePreset(observed map[string]struct{}) presetAdvice {
	if len(observed) == 0 {
		return presetAdvice{
			Status:  StatusSkip,
			Summary: "no wrapped actions recorded yet",
			Hint:    "wrap one function, run it once, or try: intentproof demo refund",
		}
	}

	bestIdx := -1
	bestCount := 0
	for i, preset := range refundPresets {
		n := countPresent(preset.required, observed)
		if n > bestCount {
			bestCount = n
			bestIdx = i
		}
	}
	if bestIdx < 0 || bestCount == 0 {
		actions := formatActionSample(observed, 5)
		return presetAdvice{
			Status:  StatusWarn,
			Summary: "no refund-flow preset match for observed actions",
			Hint:    "observed: " + actions + "; see: intentproof reference list",
		}
	}

	strictest := -1
	for i := len(refundPresets) - 1; i >= 0; i-- {
		if countPresent(refundPresets[i].required, observed) == len(refundPresets[i].required) {
			strictest = i
			break
		}
	}
	if strictest >= 0 {
		p := refundPresets[strictest]
		return presetAdvice{
			Status: StatusOK,
			Summary: fmt.Sprintf(
				"flow shape matches preset %q (%s)",
				p.name,
				p.referenceID,
			),
			Hint: "apply that preset in the dashboard when offered, or: intentproof reference fork " + p.referenceID + " --to ./policies --tenant tnt_local",
		}
	}

	p := refundPresets[bestIdx]
	missing := missingRequired(p.required, observed)
	return presetAdvice{
		Status: StatusWarn,
		Summary: fmt.Sprintf(
			"partial refund-flow shape (%d/%d actions for preset %q)",
			bestCount,
			len(p.required),
			p.name,
		),
		Hint: "still need wrapped actions: " + strings.Join(missing, ", "),
	}
}

func countPresent(required []string, observed map[string]struct{}) int {
	n := 0
	for _, action := range required {
		if observedHasAction(observed, action) {
			n++
		}
	}
	return n
}

func missingRequired(required []string, observed map[string]struct{}) []string {
	out := make([]string, 0)
	for _, action := range required {
		if !observedHasAction(observed, action) {
			out = append(out, action)
		}
	}
	return out
}

func observedHasAction(observed map[string]struct{}, required string) bool {
	if _, ok := observed[required]; ok {
		return true
	}
	for _, alias := range presetActionAliases[required] {
		if _, ok := observed[alias]; ok {
			return true
		}
	}
	return false
}

func formatActionSample(observed map[string]struct{}, limit int) string {
	actions := make([]string, 0, len(observed))
	for action := range observed {
		actions = append(actions, action)
	}
	sort.Strings(actions)
	if len(actions) > limit {
		actions = actions[:limit]
		return strings.Join(actions, ", ") + ", …"
	}
	return strings.Join(actions, ", ")
}
