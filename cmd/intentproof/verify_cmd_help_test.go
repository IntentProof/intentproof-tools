package main

import (
	"strings"
	"testing"
)

func TestRunVerifyHelp(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run([]string{"verify", "--help"}, &stdout, &stderr); code != 1 {
		t.Fatalf("help code=%d", code)
	}
	got := stderr.String()
	if !strings.Contains(got, "Usage: intentproof verify") {
		t.Fatalf("missing usage: %s", got)
	}
	if !strings.Contains(got, "counterparty-verification.md") {
		t.Fatalf("missing playbook link: %s", got)
	}
	if !strings.Contains(got, "golden/counterparty") {
		t.Fatalf("missing golden link: %s", got)
	}
}
