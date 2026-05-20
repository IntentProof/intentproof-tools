package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRunDemoRefundGetwdError(t *testing.T) {
	orig := demoGetwd
	demoGetwd = func() (string, error) {
		return "", errors.New("getwd fail")
	}
	t.Cleanup(func() { demoGetwd = orig })

	var stdout, stderr bytes.Buffer
	if code := run([]string{"demo", "refund"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "working directory:") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}
