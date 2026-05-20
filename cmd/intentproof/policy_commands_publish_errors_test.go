package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPolicyPublishCompileError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(":\n\tbad"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "publish", path}, &stdout, &stderr); code == 0 {
		t.Fatal("expected compile failure")
	}
	if !strings.Contains(stderr.String(), "compile failed") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunPolicyPublishUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runPolicyPublish(nil, &stdout, &stderr); code == 0 {
		t.Fatal("expected usage failure")
	}
}

func TestRunPolicyActivateUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runPolicyActivate(nil, &stdout, &stderr); code == 0 {
		t.Fatal("expected usage failure")
	}
}

func TestRunPolicyDiffUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runPolicyDiff(nil, &stdout, &stderr); code == 0 {
		t.Fatal("expected usage failure")
	}
}

func TestRunPolicyLintCompileError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("policy_id: only-id"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "lint", path}, &stdout, &stderr); code == 0 {
		t.Fatal("expected lint failure")
	}
}

func TestRunPolicyPublishNetworkError(t *testing.T) {
	t.Setenv("INTENTPROOF_QUERY_API_URL", "http://127.0.0.1:1")
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "")
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", "")
	dir := writeMinimalPolicyYAML(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "publish", dir}, &stdout, &stderr); code == 0 {
		t.Fatal("expected publish failure")
	}
	if !strings.Contains(stderr.String(), "publish failed") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}
