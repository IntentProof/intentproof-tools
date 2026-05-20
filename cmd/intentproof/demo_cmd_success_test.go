package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/localloop"
)

func TestRunDemoRefundSuccess(t *testing.T) {
	home := t.TempDir()
	work := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CI", "1")
	t.Chdir(work)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"demo", "refund"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(work, "demo-refund.proof.tar.zst")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(stdout.Bytes(), []byte("Demo refund scenario finished")) {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestRunDemoUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"demo"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected usage failure")
	}
}

func TestRunDemoRefundOpenBrowserHook(t *testing.T) {
	home := t.TempDir()
	work := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CI", "")
	t.Setenv(localloop.EnvLocalOpenBrowser, "1")
	t.Chdir(work)

	var opened bool
	restore := localloop.SetLaunchBrowserHook(func(string) error {
		opened = true
		return nil
	})
	defer restore()

	var stdout, stderr bytes.Buffer
	if code := run([]string{"demo", "refund"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !opened {
		t.Fatal("expected browser hook invocation")
	}
}
