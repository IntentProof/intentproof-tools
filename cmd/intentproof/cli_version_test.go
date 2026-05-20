package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunVersionCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "intentproof") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestRunDoubleDashVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--version"}, &stdout, &stderr); code != 0 {
		t.Fatal("expected success")
	}
}

func TestRunUsageWithoutCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code == 0 {
		t.Fatal("expected usage failure")
	}
}
