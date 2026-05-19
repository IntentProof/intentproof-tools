package main

import (
	"bytes"
	"os"
	"path/filepath"
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

func TestCLIVersionDoubleDash(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version code=%d", code)
	}
}

func TestCLIPolicyPublishUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "publish"}, &stdout, &stderr); code != 1 {
		t.Fatalf("publish code=%d", code)
	}
}

func TestCLIReferenceListEmptyDir(t *testing.T) {
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", t.TempDir())
	var stdout, stderr bytes.Buffer
	if code := run([]string{"reference", "list"}, &stdout, &stderr); code != 0 {
		t.Fatalf("list code=%d stderr=%s", code, stderr.String())
	}
}

func TestCLIReferenceListRejectsExtraArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"reference", "list", "extra"}, &stdout, &stderr); code != 1 {
		t.Fatalf("list code=%d", code)
	}
}

func TestCLIPolicyLintInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("not: valid: [[["), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "lint", path}, &stdout, &stderr); code != 1 {
		t.Fatalf("lint code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "lint failed") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestCLIPolicyActivateInvalidVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "activate", "p1", "nope", "--scope", "tenant"}, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stderr.String(), "invalid policy version") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestCLIUnknownTopLevelCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"not-a-command"}, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d", code)
	}
}

func TestCLIPolicyActivateMissingScope(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "activate", "tnt.demo", "1"}, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stderr.String(), "--scope is required") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}