package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestContractUsageMessage(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if got := stderr.String(); !strings.Contains(got, "Usage: intentproof-verify") {
		t.Fatalf("unexpected stderr: %s", got)
	}
}

func TestContractMissingInputFileError(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder
	missing := filepath.Join(t.TempDir(), "missing.json")
	code := run([]string{missing, missing, missing}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if got := stderr.String(); !strings.Contains(got, "error: read missing.json") {
		t.Fatalf("unexpected stderr: %s", got)
	}
}
