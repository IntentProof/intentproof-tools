package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunUnknownTopLevelCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"nope"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "Unknown command") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunPolicyUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "nope"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "Unknown policy command") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunDoctorUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"doctor", "extra"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}

func TestRunInitUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"init", "extra"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}

func TestRunVerifyUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}
