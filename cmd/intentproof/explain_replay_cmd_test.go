package main

import (
	"strings"
	"testing"
)

func TestReplayHelp(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := runReplay([]string{"--help"}, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stderr.String(), "intentproof replay") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestExplainHelp(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := runExplain([]string{"--help"}, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stderr.String(), "intentproof explain") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}
