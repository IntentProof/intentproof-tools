package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIInitAgentAndTemplates(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"dependencies":{"stripe":"^15.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	prev, _ := os.Getwd()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	var stdout, stderr bytes.Buffer
	if code := run([]string{"init", "--agent"}, &stdout, &stderr); code != 0 {
		t.Fatalf("init agent: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "IntentProof") {
		t.Fatalf("stdout=%s", stdout.String())
	}

	stdout.Reset()
	if code := run([]string{"init", "--template", "stripe-refund", "--agent"}, &stdout, &stderr); code != 0 {
		t.Fatalf("init stripe agent: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "refund") {
		t.Fatalf("stdout=%s", stdout.String())
	}

	stdout.Reset()
	if code := run([]string{"init", "--template", "stripe-refund"}, &stdout, &stderr); code != 0 {
		t.Fatalf("init stripe: %s", stderr.String())
	}

	stdout.Reset()
	if code := run([]string{"init", "--template", "nope"}, &stdout, &stderr); code != 1 {
		t.Fatalf("unknown template code=%d", code)
	}

	stdout.Reset()
	if code := run([]string{"init", "--template"}, &stdout, &stderr); code != 1 {
		t.Fatalf("missing template value code=%d", code)
	}

	t.Setenv("INTENTPROOF_AGENT", "true")
	stdout.Reset()
	if code := run([]string{"init"}, &stdout, &stderr); code != 0 {
		t.Fatalf("init via env agent: %s", stderr.String())
	}
}

func TestCLIVerifyMissingFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify", filepath.Join(t.TempDir(), "missing.tar.zst")}, &stdout, &stderr); code != 1 {
		t.Fatalf("verify code=%d", code)
	}
	if !strings.Contains(stderr.String(), "read bundle") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestCLIPolicyUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "nope"}, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d", code)
	}
}

func TestCLIDoctorHelpAndAgent(t *testing.T) {
	t.Setenv("INTENTPROOF_AGENT", "1")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"doctor", "--agent"}, &stdout, &stderr); code != 0 && code != 1 {
		t.Fatalf("doctor agent code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	if code := run([]string{"doctor", "--help"}, &stdout, &stderr); code != 1 {
		t.Fatalf("doctor help code=%d", code)
	}
	if code := run([]string{"doctor", "extra"}, &stdout, &stderr); code != 1 {
		t.Fatalf("doctor extra code=%d", code)
	}
}

func TestCLIInitHelpAndUnexpectedArg(t *testing.T) {
	root := t.TempDir()
	prev, _ := os.Getwd()
	_ = os.Chdir(root)
	t.Cleanup(func() { _ = os.Chdir(prev) })

	var stdout, stderr bytes.Buffer
	if code := run([]string{"init", "--help"}, &stdout, &stderr); code != 1 {
		t.Fatalf("help code=%d", code)
	}
	if code := run([]string{"init", "extra"}, &stdout, &stderr); code != 1 {
		t.Fatalf("extra arg code=%d", code)
	}
}

func TestCLIPolicyPublishCompileFailure(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("not: valid: yaml: [[["), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "publish", bad}, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "compile failed") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}