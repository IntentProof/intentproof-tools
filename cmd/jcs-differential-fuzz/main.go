package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("jcs-differential-fuzz", flag.ExitOnError)
	iterations := fs.Int("iterations", 256, "number of seeded inputs to compare")
	inputPath := fs.String("input", "", "compare a single JSON input file")
	seedBase := fs.Int("seed-base", 0, "starting seed offset for deterministic runs")
	artifactDir := fs.String("artifact-dir", "", "write divergence artifact here on failure")
	nodeSDK := fs.String("node-sdk", "", "path to intentproof-sdk-node checkout")
	pythonSDK := fs.String("python-sdk", "", "path to intentproof-sdk-python checkout (src root)")
	scriptsDir := fs.String("scripts-dir", "", "path to helper scripts directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	repoRoot, err := findRepoRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "repo root: %v\n", err)
		return 2
	}

	cfg := defaultConfig()
	if *nodeSDK != "" {
		cfg.NodeSDKDir = *nodeSDK
	}
	if *pythonSDK != "" {
		cfg.PythonSDKDir = *pythonSDK
	}
	if *scriptsDir != "" {
		cfg.ScriptsDir = *scriptsDir
	} else {
		cfg.ScriptsDir = filepath.Join(repoRoot, "cmd", "jcs-differential-fuzz", "scripts")
	}

	if os.Getenv("INTENTPROOF_JCS_DIFF_FUZZ_PROBE") == "1" {
		cfg.GoCanonicalize = brokenGoCanonicalize
	}

	if *inputPath != "" {
		raw, err := os.ReadFile(*inputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read input: %v\n", err)
			return 2
		}
		if err := compareOnce(cfg, raw, *artifactDir); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 1
		}
		fmt.Println("PASS: jcs differential fuzz (single input)")
		return 0
	}

	for i := 0; i < *iterations; i++ {
		seed := []byte("jcs-diff-" + strconv.Itoa(*seedBase+i))
		raw := buildEventFromSeed(seed)
		if err := compareOnce(cfg, raw, *artifactDir); err != nil {
			fmt.Fprintf(os.Stderr, "iteration %d: %v\n", i, err)
			return 1
		}
	}
	fmt.Printf("PASS: jcs differential fuzz (%d iterations)\n", *iterations)
	return 0
}

func compareOnce(cfg Config, raw []byte, artifactDir string) error {
	if !json.Valid(raw) {
		return fmt.Errorf("invalid json input")
	}
	err := compareInput(context.Background(), cfg, json.RawMessage(raw))
	if err == nil {
		return nil
	}
	var div *DivergenceError
	if artifactDir != "" && errors.As(err, &div) {
		_ = os.MkdirAll(artifactDir, 0o755)
		path := filepath.Join(artifactDir, "jcs-divergence.txt")
		_ = writeDivergenceArtifact(path, div)
		return fmt.Errorf("%w (artifact: %s)", err, path)
	}
	return err
}

func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return wd, nil
		}
		dir = parent
	}
}

func brokenGoCanonicalize(raw json.RawMessage) ([]byte, error) {
	return []byte(`{"probe":"broken"}`), nil
}
