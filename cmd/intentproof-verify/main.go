package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

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
	fs.StringVar(&outputPath, "output", "", "write signed VerificationRun JSON to path")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	remaining := fs.Args()
	if len(remaining) < 3 {
		fmt.Fprintln(stderr, "Usage: intentproof-verify [--output <path>] <flow.json> <policy.json> <attestations.jsonl>")
		return 1
	}

	flowData, err := readInputFile(remaining[0])
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	policyData, err := readInputFile(remaining[1])
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	attestationsData, err := readInputFile(remaining[2])
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	vr, err := verifier.Verify(flowData, policyData, attestationsData)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	signer, _ := crypto.NewPolicySignerFromEnv()
	if signer != nil {
		canonical, err := verifier.CanonicalRunJSON(vr)
		if err != nil {
			fmt.Fprintf(stderr, "error: canonicalize run: %v\n", err)
			return 1
		}
		digest := crypto.DigestSHA256(canonical)
		env, err := signer.Sign(context.Background(), digest)
		if err != nil {
			fmt.Fprintf(stderr, "error: sign run: %v\n", err)
			return 1
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
			fmt.Fprintf(stderr, "error: marshal run: %v\n", err)
			return 1
		}
		if err := os.WriteFile(outputPath, raw, 0o644); err != nil {
			fmt.Fprintf(stderr, "error: write output: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Fprintf(stdout, "Run Status: %s\n", vr.Status)
	return 0
}

func readInputFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	return data, nil
}
