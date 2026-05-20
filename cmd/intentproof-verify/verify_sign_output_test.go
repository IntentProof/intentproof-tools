package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "intentproof-verify") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestRunBundleVerifyFailPrintsFindings(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bad.tar")
	if err := os.WriteFile(bundlePath, []byte("not-a-bundle"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{bundlePath}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stdout.String(), "fail") && !strings.Contains(stderr.String(), "error") {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestRunBundleVerifyWithOutputWritesResult(t *testing.T) {
	optsDir := t.TempDir()
	out := filepath.Join(optsDir, "out.json")
	bundlePath := filepath.Join(optsDir, "b.tar")
	if err := os.WriteFile(bundlePath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"--output", out, bundlePath}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected verify failure")
	}
	if strings.Contains(stderr.String(), "marshal bundle result") {
		t.Fatalf("unexpected marshal path: %s", stderr.String())
	}
}

func TestRunWithLocalSigner(t *testing.T) {
	dir := t.TempDir()
	flow := filepath.Join(dir, "flow.json")
	policy := filepath.Join(dir, "policy.json")
	atts := filepath.Join(dir, "atts.jsonl")
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	t.Setenv("INTENTPROOF_POLICY_SIGNER", "local-ed25519")
	t.Setenv("INTENTPROOF_POLICY_SIGNER_KEY_ID", "test:key")
	t.Setenv("INTENTPROOF_POLICY_SIGNER_PRIVATE_KEY", "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJj")
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
	code := run([]string{flow, policy, atts}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Run Status:") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestRunUsageOnBadFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--not-a-flag"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}
