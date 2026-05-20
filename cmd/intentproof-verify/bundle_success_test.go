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

func TestRunVerifyVersionCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatal("expected success")
	}
	if !strings.Contains(stdout.String(), "intentproof-verify") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestRunBundleVerifySuccessWithOutput(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "demo.proof.tar.zst")
	outPath := filepath.Join(dir, "result.json")
	var buf bytes.Buffer
	flowJSON, _ := json.Marshal(map[string]any{
		"flow_id": "f1", "tenant_id": "tnt", "events": []any{},
	})
	if err := bundle.Create(&buf, bundle.CreateOptions{
		BundleID:    "b1",
		FlowID:      "f1",
		TenantID:    "tnt",
		FlowJSON:    flowJSON,
		EventsJSONL: []byte(`{"event_id":"e1","action":"pay","status":"ok"}` + "\n"),
		PolicyJSON:  []byte(`{"policy_id":"p1","rules":[]}`),
		RunJSON:     []byte(`{"run_id":"r1","flow_id":"f1","status":"pass","findings":[]}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"--output", outPath, bundlePath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify: %s", stderr.String())
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatal(err)
	}
}

func TestRunBundleVerifyFailWritesOutput(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bad.proof.tar.zst")
	outPath := filepath.Join(dir, "result.json")
	if err := os.WriteFile(bundlePath, []byte("not-a-bundle"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--output", outPath, bundlePath}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}

func TestRunFlowVerifyWithLocalSigner(t *testing.T) {
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", "")
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "")
	dir := t.TempDir()
	flow := filepath.Join(dir, "flow.json")
	policy := filepath.Join(dir, "policy.json")
	atts := filepath.Join(dir, "atts.jsonl")
	if err := os.WriteFile(flow, []byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(atts, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{flow, policy, atts}, &stdout, &stderr); code != 0 {
		t.Fatalf("verify: %s", stderr.String())
	}
}
