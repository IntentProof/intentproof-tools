package main

import (
	"strings"
	"testing"
)

func TestContractUnknownCommandMessage(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"bogus"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if got := stderr.String(); !strings.Contains(got, "Unknown command: bogus") {
		t.Fatalf("unexpected stderr: %s", got)
	}
}

func TestContractPolicyUsageMessage(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"policy"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if got := stderr.String(); !strings.Contains(got, "Usage: intentproof policy <subcommand>") {
		t.Fatalf("unexpected stderr: %s", got)
	}
}
