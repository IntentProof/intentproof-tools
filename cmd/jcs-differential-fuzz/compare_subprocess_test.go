package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRunNodeCanonicalizeWithFakeBinary(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "node-canonicalize.mjs"), []byte("// stub"), 0o644); err != nil {
		t.Fatalf("write script: %v", err)
	}
	fakeNode := filepath.Join(dir, "node")
	script := "#!/bin/sh\nprintf '%s' '{\"a\":1,\"b\":2}'"
	if err := os.WriteFile(fakeNode, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake node: %v", err)
	}
	cfg := Config{
		NodeBinary: fakeNode,
		ScriptsDir: dir,
		NodeSDKDir: dir,
	}
	out, err := runNodeCanonicalize(context.Background(), cfg, json.RawMessage(`{"b":2,"a":1}`))
	if err != nil {
		t.Fatalf("runNodeCanonicalize: %v", err)
	}
	if string(out) != `{"a":1,"b":2}` {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestRunPythonCanonicalizeWithFakeBinary(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "python-canonicalize.py"), []byte("# stub"), 0o644); err != nil {
		t.Fatalf("write script: %v", err)
	}
	fakePy := filepath.Join(dir, "python3")
	script := "#!/bin/sh\nprintf '%s' '{\"a\":1,\"b\":2}'"
	if err := os.WriteFile(fakePy, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake python: %v", err)
	}
	cfg := Config{
		PythonBinary: fakePy,
		ScriptsDir:   dir,
		PythonSDKDir: dir,
	}
	out, err := runPythonCanonicalize(context.Background(), cfg, json.RawMessage(`{"b":2,"a":1}`))
	if err != nil {
		t.Fatalf("runPythonCanonicalize: %v", err)
	}
	if string(out) != `{"a":1,"b":2}` {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestResolveConfigSuccess(t *testing.T) {
	nodeDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(nodeDir, "package.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.Mkdir(filepath.Join(nodeDir, "dist"), 0o755); err != nil {
		t.Fatalf("mkdir dist: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nodeDir, "dist", "signing.js"), []byte("//"), 0o644); err != nil {
		t.Fatalf("write signing.js: %v", err)
	}
	pyRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(pyRoot, "pyproject.toml"), []byte(""), 0o644); err != nil {
		t.Fatalf("write pyproject.toml: %v", err)
	}
	pySrc := filepath.Join(pyRoot, "src", "intentproof")
	if err := os.MkdirAll(pySrc, 0o755); err != nil {
		t.Fatalf("mkdir py src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pySrc, "signing.py"), []byte(""), 0o644); err != nil {
		t.Fatalf("write signing.py: %v", err)
	}
	cfg := Config{
		NodeSDKDir:   nodeDir,
		PythonSDKDir: filepath.Join(pyRoot, "src"),
	}
	resolved, err := resolveConfig(cfg)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if resolved.NodeSDKDir != nodeDir {
		t.Fatalf("node dir: %s", resolved.NodeSDKDir)
	}
}

func TestBuildEventFromSeedIncludesSignature(t *testing.T) {
	seed := make([]byte, 8)
	seed[5] = 1
	raw := buildEventFromSeed(seed)
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := obj["signature"]; !ok {
		t.Fatal("expected signature field")
	}
}

func TestCanonicalizeNodeAndPythonDispatch(t *testing.T) {
	cfg := mockConfig(t)
	raw := json.RawMessage(`{"a":1}`)
	if _, err := canonicalizeNode(context.Background(), cfg, raw); err != nil {
		t.Fatalf("canonicalizeNode: %v", err)
	}
	if _, err := canonicalizePython(context.Background(), cfg, raw); err != nil {
		t.Fatalf("canonicalizePython: %v", err)
	}
}

func TestCanonicalizeGoInvalidJSON(t *testing.T) {
	if _, err := canonicalizeGo(json.RawMessage(`{`)); err == nil {
		t.Fatal("expected error")
	}
}

func TestRunWithProbeEnv(t *testing.T) {
	t.Setenv("INTENTPROOF_JCS_DIFF_FUZZ_PROBE", "1")
	old := compareOnceHook
	defer func() { compareOnceHook = old }()
	compareOnceHook = func(cfg Config, raw []byte, artifactDir string) error {
		cfg.NodeCanonicalize = mockMatchGo(cfg)
		cfg.PythonCanonicalize = mockMatchGo(cfg)
		return compareOnce(cfg, raw, artifactDir)
	}
	if code := run([]string{"-iterations", "1"}); code != 0 {
		t.Fatalf("expected probe divergence exit 1, got %d", code)
	}
}

func TestPickBoolEmptySeed(t *testing.T) {
	if pickBool(nil, 0) {
		t.Fatal("expected false")
	}
}

func TestPickIntEmptySeed(t *testing.T) {
	if got := pickInt(nil, 0, 5, 10); got != 5 {
		t.Fatalf("got %d", got)
	}
}

func TestPickOptionalNestedEmpty(t *testing.T) {
	if pickOptionalNested([]byte{1}, 5) != nil {
		t.Fatal("expected nil")
	}
}
