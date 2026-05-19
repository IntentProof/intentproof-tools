package main

import (
	"strings"
	"testing"
)

func TestDoctorCommandUsage(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"doctor", "--help"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "Usage: intentproof doctor") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestDoctorCommandAgentMarkdown(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"doctor", "--agent"}, &stdout, &stderr)
	if code != 0 && code != 1 {
		t.Fatalf("unexpected exit code %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "# IntentProof doctor report") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestDoctorCommandRuns(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"doctor"}, &stdout, &stderr)
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "IntentProof doctor") {
		t.Fatalf("stdout=%q", stdout.String())
	}
	if code != 0 && code != 1 {
		t.Fatalf("unexpected exit code %d", code)
	}
}
