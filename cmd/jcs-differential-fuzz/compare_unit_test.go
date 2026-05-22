package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mockMatchGo(cfg Config) func(context.Context, json.RawMessage) ([]byte, error) {
	return func(_ context.Context, in json.RawMessage) ([]byte, error) {
		return cfg.GoCanonicalize(in)
	}
}

func mockConfig(t *testing.T) Config {
	t.Helper()
	cfg := defaultConfig()
	cfg.NodeCanonicalize = mockMatchGo(cfg)
	cfg.PythonCanonicalize = mockMatchGo(cfg)
	return cfg
}

func TestCanonicalizeGoStripsSignature(t *testing.T) {
	raw := json.RawMessage(`{"a":1,"signature":{"alg":"ed25519","key_id":"k","value":"x"}}`)
	out, err := canonicalizeGo(raw)
	if err != nil {
		t.Fatalf("canonicalizeGo: %v", err)
	}
	if strings.Contains(string(out), "signature") {
		t.Fatalf("signature not stripped: %s", out)
	}
}

func TestCompareInputMockedMatch(t *testing.T) {
	raw := json.RawMessage(`{"b":2,"a":1}`)
	if err := compareInput(t.Context(), mockConfig(t), raw); err != nil {
		t.Fatalf("compare: %v", err)
	}
}

func TestCompareInputMockedDivergence(t *testing.T) {
	cfg := mockConfig(t)
	cfg.NodeCanonicalize = func(context.Context, json.RawMessage) ([]byte, error) {
		return []byte(`{"bad":true}`), nil
	}
	raw := json.RawMessage(`{"a":1}`)
	err := compareInput(t.Context(), cfg, raw)
	var div *DivergenceError
	if !errors.As(err, &div) {
		t.Fatalf("expected DivergenceError, got %v", err)
	}
	if div.Error() == "" {
		t.Fatal("expected error string")
	}
}

func TestCompareInputGoError(t *testing.T) {
	cfg := mockConfig(t)
	cfg.GoCanonicalize = func(json.RawMessage) ([]byte, error) {
		return nil, errors.New("boom")
	}
	err := compareInput(t.Context(), cfg, json.RawMessage(`{"a":1}`))
	if err == nil || !strings.Contains(err.Error(), "go canonicalize") {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestCompareInputNodeError(t *testing.T) {
	cfg := mockConfig(t)
	cfg.NodeCanonicalize = func(context.Context, json.RawMessage) ([]byte, error) {
		return nil, errors.New("node fail")
	}
	err := compareInput(t.Context(), cfg, json.RawMessage(`{"a":1}`))
	if err == nil || !strings.Contains(err.Error(), "node canonicalize") {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestCompareInputPythonError(t *testing.T) {
	cfg := mockConfig(t)
	cfg.PythonCanonicalize = func(context.Context, json.RawMessage) ([]byte, error) {
		return nil, errors.New("py fail")
	}
	err := compareInput(t.Context(), cfg, json.RawMessage(`{"a":1}`))
	if err == nil || !strings.Contains(err.Error(), "python canonicalize") {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestResolveConfigMissingSDK(t *testing.T) {
	cfg := defaultConfig()
	cfg.NodeSDKDir = filepath.Join(t.TempDir(), "missing-node")
	cfg.PythonSDKDir = filepath.Join(t.TempDir(), "missing-py")
	_, err := resolveConfig(cfg)
	if err == nil {
		t.Fatal("expected error for missing sdk")
	}
}

func TestCompareOnceInvalidJSON(t *testing.T) {
	err := compareOnce(mockConfig(t), []byte("{"), "")
	if err == nil || !strings.Contains(err.Error(), "invalid json") {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestCompareOnceArtifactPath(t *testing.T) {
	cfg := mockConfig(t)
	cfg.NodeCanonicalize = func(context.Context, json.RawMessage) ([]byte, error) {
		return []byte(`{"x":1}`), nil
	}
	dir := t.TempDir()
	err := compareOnce(cfg, []byte(`{"a":1}`), dir)
	if err == nil || !strings.Contains(err.Error(), "artifact:") {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestTruncateForError(t *testing.T) {
	long := strings.Repeat("x", 200)
	if !strings.HasSuffix(truncateForError([]byte(long)), "...") {
		t.Fatal("expected truncation")
	}
	if truncateForError([]byte("short")) != "short" {
		t.Fatal("expected unchanged short string")
	}
}

func TestFindRepoRoot(t *testing.T) {
	root, err := findRepoRoot()
	if err != nil {
		t.Fatalf("findRepoRoot: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("missing go.mod under %s", root)
	}
}
