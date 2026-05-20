package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRunDemoRefundCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("demo integration")
	}
	home := t.TempDir()
	work := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(work)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"demo", "refund"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(work, "demo-refund.proof.tar.zst")); err != nil {
		t.Fatalf("bundle: %v", err)
	}
}

func TestRunDemoUnknownScenario(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"demo", "unknown"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}
