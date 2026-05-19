package doctor

import (
	"strings"
	"testing"
	"time"
)

func TestFormatLastEventAgeAndActionSample(t *testing.T) {
	if got := formatLastEventAge(""); got != "" {
		t.Fatalf("empty=%q", got)
	}
	if got := formatLastEventAge("not-a-time"); got != "not-a-time" {
		t.Fatalf("invalid=%q", got)
	}
	recent := time.Now().UTC().Add(-30 * time.Second).Format(time.RFC3339)
	if got := formatLastEventAge(recent); !strings.Contains(got, "ago") {
		t.Fatalf("recent=%q", got)
	}
	old := time.Now().UTC().Add(-2 * time.Minute).Format(time.RFC3339)
	if got := formatLastEventAge(old); !strings.Contains(got, "ago") {
		t.Fatalf("old=%q", got)
	}

	sample := formatActionSample(map[string]struct{}{
		"alpha": {}, "beta": {}, "gamma": {},
	}, 2)
	if !strings.Contains(sample, "…") {
		t.Fatalf("sample=%q", sample)
	}
	if got := formatActionSample(map[string]struct{}{"only": {}}, 3); got != "only" {
		t.Fatalf("single=%q", got)
	}
}

func TestObservedHasActionAliases(t *testing.T) {
	observed := map[string]struct{}{"ledger.entry.write": {}}
	if !observedHasAction(observed, "ledger.refund.record") {
		t.Fatal("expected alias match")
	}
	if observedHasAction(observed, "missing.action") {
		t.Fatal("unexpected match")
	}
}
