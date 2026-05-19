package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/demo"
)

func TestRunBundleVerifyPass(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	home := t.TempDir()
	work := t.TempDir()
	if err := demo.RunRefund(t.Context(), demo.Options{
		HomeDir:     home,
		WorkDir:     work,
		OpenBrowser: false,
	}); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(work, "demo-refund.proof.tar.zst")
	var stdout, stderr strings.Builder
	code := run([]string{"--output", filepath.Join(work, "out.json"), bundlePath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify bundle: code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(work, "out.json")); err != nil {
		t.Fatal(err)
	}
}

func TestRunVersionFlag(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run([]string{"--version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stdout.String(), "intentproof-verify") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}
