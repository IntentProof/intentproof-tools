package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func sdkDirs(t *testing.T) (nodeDir, pythonDir string, ok bool) {
	t.Helper()
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	nodeDir = os.Getenv("INTENTPROOF_NODE_SDK_DIR")
	pythonDir = os.Getenv("INTENTPROOF_PYTHON_SDK_DIR")
	if nodeDir == "" {
		nodeDir = filepath.Join(repoRoot, "..", "intentproof-sdk-node")
	}
	if pythonDir == "" {
		pythonDir = filepath.Join(repoRoot, "..", "intentproof-sdk-python", "src")
	}
	if _, err := os.Stat(filepath.Join(nodeDir, "dist", "signing.js")); err != nil {
		t.Skipf("node sdk dist missing (run npm run build): %v", err)
	}
	if _, err := os.Stat(filepath.Join(pythonDir, "intentproof", "signing.py")); err != nil {
		t.Skipf("python sdk missing: %v", err)
	}
	return nodeDir, pythonDir, true
}

func testConfig(t *testing.T) Config {
	t.Helper()
	nodeDir, pythonDir, ok := sdkDirs(t)
	if !ok {
		t.Fatal("unreachable")
	}
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	return Config{
		NodeSDKDir:   nodeDir,
		PythonSDKDir: pythonDir,
		ScriptsDir:   filepath.Join(repoRoot, "cmd", "jcs-differential-fuzz", "scripts"),
	}
}

func TestCompareGoldenSigningFixture(t *testing.T) {
	cfg := testConfig(t)
	nodeDir, _, _ := sdkDirs(t)
	fixture := filepath.Join(nodeDir, "tests", "fixtures", "signing_unsigned_event.json")
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := compareInput(t.Context(), cfg, raw); err != nil {
		t.Fatalf("compare golden fixture: %v", err)
	}
}

func TestCompareGeneratedSeeds(t *testing.T) {
	cfg := testConfig(t)
	for i := range 32 {
		seed := []byte("jcs-diff-" + strconv.Itoa(i))
		raw := buildEventFromSeed(seed)
		if err := compareInput(t.Context(), cfg, raw); err != nil {
			t.Fatalf("seed %q: %v", seed, err)
		}
	}
}

func TestProbeDetectsDivergenceWithArtifact(t *testing.T) {
	cfg := testConfig(t)
	cfg.GoCanonicalize = brokenGoCanonicalize
	raw := buildEventFromSeed([]byte("probe-seed"))
	dir := t.TempDir()
	err := compareOnce(cfg, raw, dir)
	if err == nil {
		t.Fatal("expected divergence")
	}
	if !strings.Contains(err.Error(), "artifact:") {
		t.Fatalf("expected artifact path in error, got: %v", err)
	}
	artifact := filepath.Join(dir, "jcs-divergence.txt")
	body, readErr := os.ReadFile(artifact)
	if readErr != nil {
		t.Fatalf("read artifact: %v", readErr)
	}
	if !strings.Contains(string(body), string(raw)) {
		t.Fatalf("artifact missing input bytes: %s", body)
	}
}

func TestWriteDivergenceArtifact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	err := &DivergenceError{
		Input:     []byte(`{"a":1}`),
		GoOut:     []byte(`{"a":1}`),
		NodeOut:   []byte(`{"b":2}`),
		PythonOut: []byte(`{"a":1}`),
	}
	if errWrite := writeDivergenceArtifact(path, err); errWrite != nil {
		t.Fatalf("write: %v", errWrite)
	}
	body, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	if !strings.Contains(string(body), `input={"a":1}`) {
		t.Fatalf("unexpected body: %s", body)
	}
}
