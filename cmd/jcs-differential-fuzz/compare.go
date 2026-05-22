package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/canon"
)

const defaultTimeout = 30 * time.Second

// Config locates SDK checkouts and helper scripts for subprocess canonicalizers.
type Config struct {
	NodeSDKDir         string
	PythonSDKDir       string
	ScriptsDir         string
	Timeout            time.Duration
	NodeBinary         string
	PythonBinary       string
	GoCanonicalize     func(json.RawMessage) ([]byte, error)
	NodeCanonicalize   func(context.Context, json.RawMessage) ([]byte, error)
	PythonCanonicalize func(context.Context, json.RawMessage) ([]byte, error)
}

func defaultConfig() Config {
	return Config{
		Timeout:        defaultTimeout,
		NodeBinary:     "node",
		PythonBinary:   "python3",
		GoCanonicalize: canonicalizeGo,
	}
}

// DivergenceError is returned when Go, Node, and Python canonicalizers disagree.
type DivergenceError struct {
	Input     []byte
	GoOut     []byte
	NodeOut   []byte
	PythonOut []byte
	NodeErr   error
	PythonErr error
}

func (e *DivergenceError) Error() string {
	return fmt.Sprintf(
		"jcs divergence: go=%q node=%q python=%q input=%s",
		truncateForError(e.GoOut),
		truncateForError(e.NodeOut),
		truncateForError(e.PythonOut),
		truncateForError(e.Input),
	)
}

func truncateForError(b []byte) string {
	const max = 120
	s := string(b)
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func resolveConfig(cfg Config) (Config, error) {
	out := cfg
	if out.Timeout == 0 {
		out.Timeout = defaultTimeout
	}
	if out.NodeBinary == "" {
		out.NodeBinary = "node"
	}
	if out.PythonBinary == "" {
		out.PythonBinary = "python3"
	}
	if out.GoCanonicalize == nil {
		out.GoCanonicalize = canonicalizeGo
	}
	if out.NodeCanonicalize != nil && out.PythonCanonicalize != nil {
		return out, nil
	}
	if out.ScriptsDir == "" {
		out.ScriptsDir = filepath.Join("cmd", "jcs-differential-fuzz", "scripts")
	}
	if out.NodeSDKDir == "" {
		out.NodeSDKDir = os.Getenv("INTENTPROOF_NODE_SDK_DIR")
	}
	if out.PythonSDKDir == "" {
		out.PythonSDKDir = os.Getenv("INTENTPROOF_PYTHON_SDK_DIR")
	}
	repoRoot, _ := findRepoRoot()
	if out.NodeSDKDir == "" && repoRoot != "" {
		out.NodeSDKDir = filepath.Join(repoRoot, "..", "intentproof-sdk-node")
	}
	if out.PythonSDKDir == "" && repoRoot != "" {
		out.PythonSDKDir = filepath.Join(repoRoot, "..", "intentproof-sdk-python", "src")
	}
	if out.NodeSDKDir == "" || out.PythonSDKDir == "" {
		return out, errors.New("node and python SDK directories are required")
	}
	nodePkg := filepath.Join(out.NodeSDKDir, "package.json")
	if _, err := os.Stat(nodePkg); err != nil {
		return out, fmt.Errorf("node sdk not found at %s: %w", out.NodeSDKDir, err)
	}
	nodeSigning := filepath.Join(out.NodeSDKDir, "dist", "signing.js")
	if _, err := os.Stat(nodeSigning); err != nil {
		return out, fmt.Errorf("node sdk dist missing (run npm run build in %s): %w", out.NodeSDKDir, err)
	}
	pyRoot, err := pythonSDKSrcRoot(out.PythonSDKDir)
	if err != nil {
		return out, fmt.Errorf("python sdk not found at %s: %w", out.PythonSDKDir, err)
	}
	out.PythonSDKDir = pyRoot
	return out, nil
}

func pythonSDKSrcRoot(pythonSDKDir string) (string, error) {
	candidates := []string{pythonSDKDir}
	if filepath.Base(pythonSDKDir) != "src" {
		candidates = append(candidates, filepath.Join(pythonSDKDir, "src"))
	}
	for _, root := range candidates {
		if _, err := os.Stat(filepath.Join(root, "intentproof", "canon.py")); err == nil {
			return root, nil
		}
	}
	return "", fmt.Errorf("canon module not found under %s", pythonSDKDir)
}

func canonicalizeGo(raw json.RawMessage) ([]byte, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if obj, ok := value.(map[string]any); ok {
		delete(obj, "signature")
	}
	return canon.Marshal(value)
}

func compareInput(ctx context.Context, cfg Config, input json.RawMessage) error {
	cfg, err := resolveConfig(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	goOut, err := cfg.GoCanonicalize(input)
	if err != nil {
		return fmt.Errorf("go canonicalize: %w", err)
	}

	nodeOut, nodeErr := canonicalizeNode(ctx, cfg, input)
	pyOut, pyErr := canonicalizePython(ctx, cfg, input)
	if nodeErr != nil {
		return fmt.Errorf("node canonicalize: %w", nodeErr)
	}
	if pyErr != nil {
		return fmt.Errorf("python canonicalize: %w", pyErr)
	}

	if bytes.Equal(goOut, nodeOut) && bytes.Equal(goOut, pyOut) {
		return nil
	}
	return &DivergenceError{
		Input:     append([]byte(nil), input...),
		GoOut:     goOut,
		NodeOut:   nodeOut,
		PythonOut: pyOut,
	}
}

func canonicalizeNode(ctx context.Context, cfg Config, input json.RawMessage) ([]byte, error) {
	if cfg.NodeCanonicalize != nil {
		return cfg.NodeCanonicalize(ctx, input)
	}
	return runNodeCanonicalize(ctx, cfg, input)
}

func canonicalizePython(ctx context.Context, cfg Config, input json.RawMessage) ([]byte, error) {
	if cfg.PythonCanonicalize != nil {
		return cfg.PythonCanonicalize(ctx, input)
	}
	return runPythonCanonicalize(ctx, cfg, input)
}

func runNodeCanonicalize(ctx context.Context, cfg Config, input json.RawMessage) ([]byte, error) {
	script := filepath.Join(cfg.ScriptsDir, "node-canonicalize.mjs")
	cmd := exec.CommandContext(ctx, cfg.NodeBinary, script, cfg.NodeSDKDir)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func runPythonCanonicalize(ctx context.Context, cfg Config, input json.RawMessage) ([]byte, error) {
	script := filepath.Join(cfg.ScriptsDir, "python-canonicalize.py")
	cmd := exec.CommandContext(ctx, cfg.PythonBinary, script, cfg.PythonSDKDir)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func writeDivergenceArtifact(path string, err *DivergenceError) error {
	var b strings.Builder
	fmt.Fprintf(&b, "input=%s\n", string(err.Input))
	fmt.Fprintf(&b, "go=%s\n", string(err.GoOut))
	fmt.Fprintf(&b, "node=%s\n", string(err.NodeOut))
	fmt.Fprintf(&b, "python=%s\n", string(err.PythonOut))
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
