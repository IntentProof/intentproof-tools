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

func TestContractVersionMessage(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"--version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if got := stdout.String(); !strings.Contains(got, "intentproof dev") {
		t.Fatalf("unexpected stdout: %s", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %s", stderr.String())
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
