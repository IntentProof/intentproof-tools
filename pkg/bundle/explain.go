package bundle

import (
	"fmt"
	"strings"
)

// ReasonDescriber resolves stable reason codes to human copy (for example from
// intentproof-spec semantics/reasons.json). When nil, only bundled summaries
// are shown.
type ReasonDescriber func(code string) (title string, detail string, ok bool)

// FormatExplain renders a human-readable verification summary.
func FormatExplain(vr *VerifyResult, bundledRun map[string]interface{}, replay *verifierRunView, describe ReasonDescriber) string {
	var b strings.Builder
	if vr != nil {
		marker := "✓ pass"
		if vr.Status != "pass" {
			marker = "✗ fail"
		}
		fmt.Fprintf(&b, "%s: %s (bundle integrity)\n", marker, vr.Reason)
		if len(vr.Findings) > 0 && vr.Status != "pass" {
			b.WriteString("\nIntegrity findings:\n")
			for _, f := range vr.Findings {
				fmt.Fprintf(&b, "  - %s\n", f)
			}
		}
	}

	if replay != nil {
		b.WriteString("\nPolicy replay:\n")
		fmt.Fprintf(&b, "  status: %s\n", replay.Status)
		if bundledStatus, ok := bundledRunStatus(bundledRun); ok {
			match := "matches"
			if bundledStatus != replay.Status {
				match = "differs from bundled run.json"
			}
			fmt.Fprintf(&b, "  bundled run.json status: %s (%s)\n", bundledStatus, match)
		}
		for _, f := range replay.Findings {
			writePolicyFinding(&b, f, describe)
		}
	} else if len(policyFindingsFromRun(bundledRun)) > 0 {
		b.WriteString("\nPolicy findings (from bundled run.json):\n")
		for _, f := range policyFindingsFromRun(bundledRun) {
			writePolicyFinding(&b, f, describe)
		}
	}

	return strings.TrimRight(b.String(), "\n") + "\n"
}

type verifierRunView struct {
	Status   string
	Findings []policyFindingView
}

// NewVerifierRunView adapts a verification run for explain output.
func NewVerifierRunView(status string, findings []map[string]interface{}) *verifierRunView {
	out := &verifierRunView{Status: status}
	for _, f := range findings {
		out.Findings = append(out.Findings, policyFindingFromMap(f))
	}
	return out
}

type policyFindingView struct {
	Outcome      string
	Reason       string
	HumanSummary string
}

func policyFindingFromMap(m map[string]interface{}) policyFindingView {
	v := policyFindingView{}
	if s, ok := m["outcome"].(string); ok {
		v.Outcome = s
	}
	if s, ok := m["reason"].(string); ok {
		v.Reason = s
	}
	if s, ok := m["human_summary"].(string); ok {
		v.HumanSummary = s
	}
	return v
}

func policyFindingsFromRun(run map[string]interface{}) []policyFindingView {
	if run == nil {
		return nil
	}
	raw, ok := run["findings"].([]interface{})
	if !ok {
		return nil
	}
	out := make([]policyFindingView, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, policyFindingFromMap(m))
	}
	return out
}

func bundledRunStatus(run map[string]interface{}) (string, bool) {
	if run == nil {
		return "", false
	}
	s, ok := run["status"].(string)
	return s, ok && s != ""
}

func writePolicyFinding(b *strings.Builder, f policyFindingView, describe ReasonDescriber) {
	if f.Outcome == "pass" {
		return
	}
	code := f.Reason
	if code == "" {
		code = "unknown"
	}
	fmt.Fprintf(b, "\n  [%s] %s\n", f.Outcome, code)
	if f.HumanSummary != "" {
		fmt.Fprintf(b, "    %s\n", f.HumanSummary)
	}
	if describe != nil {
		if title, detail, ok := describe(code); ok {
			if title != "" {
				fmt.Fprintf(b, "    %s\n", title)
			}
			if detail != "" && detail != title {
				fmt.Fprintf(b, "    %s\n", detail)
			}
		}
	}
}
