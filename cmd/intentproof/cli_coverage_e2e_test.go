package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLIUsageAndVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 1 {
		t.Fatalf("empty args code=%d", code)
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "intentproof") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestCLIPolicyAndReferenceUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy"}, &stdout, &stderr); code != 1 {
		t.Fatalf("policy code=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"reference"}, &stdout, &stderr); code != 1 {
		t.Fatalf("reference code=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"reference", "fork"}, &stdout, &stderr); code != 1 {
		t.Fatalf("reference fork code=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"reference", "nope"}, &stdout, &stderr); code != 1 {
		t.Fatalf("reference unknown code=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"policy", "diff"}, &stdout, &stderr); code != 1 {
		t.Fatalf("policy diff code=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"policy", "test"}, &stdout, &stderr); code != 1 {
		t.Fatalf("policy test code=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"policy", "activate"}, &stdout, &stderr); code != 1 {
		t.Fatalf("policy activate code=%d", code)
	}
}

func TestCLIPolicyLintMissingFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "lint"}, &stdout, &stderr); code != 1 {
		t.Fatalf("lint code=%d", code)
	}
}

func TestCLIVerifyMissingBundle(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify"}, &stdout, &stderr); code != 1 {
		t.Fatalf("verify code=%d", code)
	}
}

func TestCLIDoctorAgentOutputEnv(t *testing.T) {
	t.Setenv("INTENTPROOF_DOCTOR_AGENT_OUTPUT", "1")
	var stdout, stderr bytes.Buffer
	_ = run([]string{"doctor"}, &stdout, &stderr)
}
