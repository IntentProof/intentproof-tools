package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/intentproof/intentproof-tools/pkg/bundle"
	"github.com/intentproof/intentproof-tools/pkg/crypto"
	"github.com/intentproof/intentproof-tools/pkg/verifier"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	var outputPath string
	fs := flag.NewFlagSet("intentproof-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&outputPath, "output", "", "write JSON result to path")
	if err := fs.Parse(args); err != nil {
		return writeError(stderr, "error: %v\n", err)
	}
	remaining := fs.Args()
	if len(remaining) == 1 {
		return runBundleVerify(remaining[0], outputPath, stdout, stderr)
	}
	if len(remaining) < 3 {
		writeUsage(stderr)
		return 1
	}

	flowData, err := readInputFile(remaining[0])
	if err != nil {
		return writeError(stderr, "error: %v\n", err)
	}
	policyData, err := readInputFile(remaining[1])
	if err != nil {
		return writeError(stderr, "error: %v\n", err)
	}
	attestationsData, err := readInputFile(remaining[2])
	if err != nil {
		return writeError(stderr, "error: %v\n", err)
	}

	vr, err := verifier.Verify(flowData, policyData, attestationsData)
	if err != nil {
		return writeError(stderr, "error: %v\n", err)
	}

	signer, err := crypto.NewPolicySignerFromEnv()
	if err != nil {
		return writeError(stderr, "error: load signer: %v\n", err)
	}
	if signer != nil {
		canonical, err := verifier.CanonicalRunJSON(vr)
		if err != nil {
			return writeError(stderr, "error: canonicalize run: %v\n", err)
		}
		digest := crypto.DigestSHA256(canonical)
		env, err := signer.Sign(context.Background(), digest)
		if err != nil {
			return writeError(stderr, "error: sign run: %v\n", err)
		}
		vr.Signature = map[string]interface{}{
			"alg":    env.Alg,
			"key_id": env.KeyID,
			"value":  env.Value,
		}
	}

	if outputPath != "" {
		raw, err := json.MarshalIndent(vr, "", "  ")
		if err != nil {
			return writeError(stderr, "error: marshal run: %v\n", err)
		}
		if err := os.WriteFile(outputPath, raw, 0o644); err != nil {
			return writeError(stderr, "error: write output: %v\n", err)
		}
		return 0
	}

	_, _ = fmt.Fprintf(stdout, "Run Status: %s\n", vr.Status)
	return 0
}

func runBundleVerify(path string, outputPath string, stdout io.Writer, stderr io.Writer) int {
	raw, err := readInputFile(path)
	if err != nil {
		return writeError(stderr, "error: %v\n", err)
	}
	vr, err := bundle.Verify(bytes.NewReader(raw), nil)
	if err != nil {
		return writeError(stderr, "error: verify bundle: %v\n", err)
	}
	if outputPath != "" {
		raw, err := json.MarshalIndent(vr, "", "  ")
		if err != nil {
			return writeError(stderr, "error: marshal bundle result: %v\n", err)
		}
		if err := os.WriteFile(outputPath, raw, 0o644); err != nil {
			return writeError(stderr, "error: write output: %v\n", err)
		}
		if vr.Status != "pass" {
			return 1
		}
		return 0
	}
	marker := "✓ pass"
	if vr.Status != "pass" {
		marker = "✗ fail"
	}
	_, _ = fmt.Fprintf(stdout, "%s: %s\n", marker, vr.Reason)
	for _, finding := range vr.Findings {
		_, _ = fmt.Fprintf(stdout, "- %s\n", finding)
	}
	if vr.Status != "pass" {
		return 1
	}
	return 0
}

func writeError(w io.Writer, format string, a ...any) int {
	_, _ = fmt.Fprintf(w, format, a...)
	return 1
}

func writeUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: intentproof-verify [--output <path>] <flow.json> <policy.json> <attestations.jsonl>")
	_, _ = fmt.Fprintln(w, "       intentproof-verify <bundle.proof.tar.zst>")
}

func readInputFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	return data, nil
}
