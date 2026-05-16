package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/bundle"
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

func TestContractBundleVerifyPassOutput(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "test.proof.tar.zst")
	writeTestBundle(t, bundlePath)

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{bundlePath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d stderr=%s", code, stderr.String())
	}
	if got := stdout.String(); !strings.Contains(got, "✓ pass: bundle.verify_pass") ||
		!strings.Contains(got, "- bundle.verify_pass") {
		t.Fatalf("unexpected stdout: %s", got)
	}
}

func TestContractBundleVerifyWritesOutput(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "test.proof.tar.zst")
	outputPath := filepath.Join(dir, "result.json")
	writeTestBundle(t, bundlePath)

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"--output", outputPath, bundlePath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d stderr=%s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "" {
		t.Fatalf("expected empty stdout with --output, got %s", stdout.String())
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var result bundle.VerifyResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if result.Status != "pass" || result.Reason != "bundle.verify_pass" {
		t.Fatalf("unexpected output result: %#v", result)
	}
}

func TestContractBundleVerifyFailOutput(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "empty.proof.tar.zst")
	if err := os.WriteFile(bundlePath, nil, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{bundlePath}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d stderr=%s", code, stderr.String())
	}
	if got := stdout.String(); !strings.Contains(got, "✗ fail: bundle.manifest_missing") {
		t.Fatalf("unexpected stdout: %s", got)
	}
}

func writeTestBundle(t *testing.T, path string) {
	t.Helper()
	var buf bytes.Buffer
	if err := bundle.Create(&buf, bundle.CreateOptions{
		BundleID:          "bundle_test",
		FlowID:            "flow_test",
		TenantID:          "tnt_test",
		FlowJSON:          []byte(`{"flow_id":"flow_test","tenant_id":"tnt_test","events":[]}`),
		EventsJSONL:       []byte(`{"event_id":"evt_test"}`),
		AttestationsJSONL: nil,
		PolicyJSON:        []byte(`{"policy_id":"policy_test","rules":[]}`),
		RunJSON:           []byte(`{"run_id":"run_test","status":"pass"}`),
	}); err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
}
