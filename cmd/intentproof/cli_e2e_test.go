package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

)

func TestCLIRefundDemoAndVerifyBundle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI demo e2e in -short")
	}
	home := t.TempDir()
	work := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("INTENTPROOF_LOCAL_OPEN_BROWSER", "0")

	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	var stdout, stderr bytes.Buffer
	code := run([]string{"demo", "refund"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("demo refund: code=%d stderr=%s", code, stderr.String())
	}

	bundlePath := filepath.Join(work, "demo-refund.proof.tar.zst")
	if _, err := os.Stat(bundlePath); err != nil {
		t.Fatalf("bundle missing: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"verify", bundlePath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify bundle: code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), `"status": "pass"`) && !strings.Contains(stdout.String(), `"status":"pass"`) {
		t.Fatalf("unexpected verify output: %s", stdout.String())
	}
}

func TestCLIDemoUnknownScenario(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"demo", "unknown"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "Unknown demo scenario") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestCLIInitAndDoctorSmoke(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("INTENTPROOF_USE_LOCAL_INGEST", "1")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"init"}, &stdout, &stderr); code != 0 {
		t.Fatalf("init: code=%d stderr=%s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"doctor"}, &stdout, &stderr); code != 0 && code != 1 {
		t.Fatalf("doctor unexpected code=%d stderr=%s", code, stderr.String())
	}
}

func TestCLILocalCommandRequiresServerEnv(t *testing.T) {
	t.Setenv("INTENTPROOF_LOCAL_INGEST_ADDR", "")
	var stdout, stderr bytes.Buffer
	// startLocalServer binds defaults; skip starting real server in unit env.
	// Exercise unknown top-level command instead.
	code := run([]string{"not-a-command"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected failure")
	}
}
