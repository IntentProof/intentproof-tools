package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunSingleInputMocked(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "event.json")
	if err := os.WriteFile(input, []byte(`{"b":2,"a":1}`), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	old := compareOnceHook
	defer func() { compareOnceHook = old }()
	compareOnceHook = func(cfg Config, raw []byte, artifactDir string) error {
		cfg.NodeCanonicalize = mockMatchGo(cfg)
		cfg.PythonCanonicalize = mockMatchGo(cfg)
		return compareOnce(cfg, raw, artifactDir)
	}
	if code := run([]string{"-input", input, "-node-sdk", "unused", "-python-sdk", "unused"}); code != 0 {
		t.Fatalf("run exit code: %d", code)
	}
}

func TestRunIterationsMocked(t *testing.T) {
	old := compareOnceHook
	defer func() { compareOnceHook = old }()
	compareOnceHook = func(cfg Config, raw []byte, artifactDir string) error {
		cfg.NodeCanonicalize = mockMatchGo(cfg)
		cfg.PythonCanonicalize = mockMatchGo(cfg)
		return compareOnce(cfg, raw, artifactDir)
	}
	if code := run([]string{"-iterations", "4", "-node-sdk", "unused", "-python-sdk", "unused"}); code != 0 {
		t.Fatalf("run exit code: %d", code)
	}
}

func TestRunMissingInputFile(t *testing.T) {
	if code := run([]string{"-input", filepath.Join(t.TempDir(), "missing.json")}); code != 2 {
		t.Fatalf("run exit code: %d", code)
	}
}
