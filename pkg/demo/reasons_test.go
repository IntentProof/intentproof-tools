package demo

import (
	"strings"
	"testing"
)

func TestLoadReasonCopyMissingRequired(t *testing.T) {
	copy, err := LoadReasonCopy("fail.required.missing")
	if err != nil {
		t.Fatal(err)
	}
	if copy.Code != "fail.required.missing" {
		t.Fatalf("code=%q", copy.Code)
	}
	if copy.Title == "" {
		t.Fatal("expected catalog title")
	}
	out := FormatFindingCopy(copy)
	if !strings.Contains(out, "fail.required.missing") || !strings.Contains(out, copy.Title) {
		t.Fatalf("unexpected format: %s", out)
	}
}

func TestLoadRefundScenario(t *testing.T) {
	scenario, err := LoadRefundScenario()
	if err != nil {
		t.Fatal(err)
	}
	if scenario.HappyPath.CorrelationID == "" || scenario.DivergentPath.CorrelationID == "" {
		t.Fatal("missing correlation ids")
	}
	if len(scenario.PolicyYAML) == 0 || len(scenario.StripeBody) == 0 {
		t.Fatal("expected policy and stripe bytes")
	}
}
