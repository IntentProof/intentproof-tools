package bundle

import (
	"strings"
	"testing"
)

func TestFormatExplainIntegrityFail(t *testing.T) {
	out := FormatExplain(&VerifyResult{
		Status:   "fail",
		Reason:   "bundle.file_missing",
		Findings: []string{"file_missing:run.json"},
	}, nil, nil, nil)
	for _, part := range []string{"✗ fail", "bundle.file_missing", "file_missing:run.json"} {
		if !strings.Contains(out, part) {
			t.Fatalf("missing %q in:\n%s", part, out)
		}
	}
}

func TestWritePolicyFindingSkipsPass(t *testing.T) {
	var b strings.Builder
	writePolicyFinding(&b, policyFindingView{Outcome: "pass", Reason: "ok"}, nil)
	if b.Len() != 0 {
		t.Fatalf("got %q", b.String())
	}
}

func TestFormatExplainPolicyFinding(t *testing.T) {
	replay := NewVerifierRunView("fail", []map[string]interface{}{
		{
			"outcome":       "fail",
			"reason":        "fail.required.missing",
			"human_summary": "missing notify step",
		},
	})
	out := FormatExplain(
		&VerifyResult{Status: "pass", Reason: "bundle.verify_pass"},
		map[string]interface{}{"status": "fail"},
		replay,
		nil,
	)
	for _, part := range []string{
		"bundle integrity",
		"Policy replay",
		"fail.required.missing",
		"missing notify step",
	} {
		if !strings.Contains(out, part) {
			t.Fatalf("missing %q in:\n%s", part, out)
		}
	}
}
