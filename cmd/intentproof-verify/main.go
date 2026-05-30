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
	"strings"

	"github.com/intentproof/intentproof-tools/pkg/buildinfo"
	"github.com/intentproof/intentproof-tools/pkg/bundle"
	"github.com/intentproof/intentproof-tools/pkg/crypto"
	"github.com/intentproof/intentproof-tools/pkg/demo"
	"github.com/intentproof/intentproof-tools/pkg/verifier"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Fprintln(stdout, buildinfo.String("intentproof-verify"))
		return 0
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		fmt.Fprintln(stderr, verifyUsage())
		return 1
	}
	if len(args) >= 2 {
		switch args[0] {
		case "explain":
			return runExplain(args[1:], stdout, stderr)
		case "replay":
			return runReplay(args[1:], stdout, stderr)
		}
	}

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
	_, _ = fmt.Fprintln(w, verifyUsage())
}

func runExplain(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(stderr, explainUsage())
		return 1
	}
	if len(args) < 1 {
		fmt.Fprintln(stderr, explainUsage())
		return 1
	}
	raw, err := readInputFile(args[0])
	if err != nil {
		return writeError(stderr, "error: %v\n", err)
	}
	text, code, err := bundle.ExplainFromReader(bytes.NewReader(raw), verifyReasonDescriber)
	if err != nil {
		_ = writeError(stderr, "error: %v\n", err)
	}
	_, _ = io.WriteString(stdout, text)
	return code
}

func runReplay(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(stderr, replayUsage())
		return 1
	}
	if len(args) < 1 {
		fmt.Fprintln(stderr, replayUsage())
		return 1
	}
	raw, err := readInputFile(args[0])
	if err != nil {
		return writeError(stderr, "error: %v\n", err)
	}
	b, err := bundle.Read(bytes.NewReader(raw))
	if err != nil {
		return writeError(stderr, "error: %v\n", err)
	}
	vr, err := bundle.VerifyBundle(b, nil)
	if err != nil {
		return writeError(stderr, "error: verify bundle: %v\n", err)
	}
	if vr.Status != "pass" {
		return writeError(stderr, "error: bundle integrity failed: %s\n", vr.Reason)
	}
	run, err := bundle.ReplayPolicy(b)
	if err != nil {
		return writeError(stderr, "error: policy replay: %v\n", err)
	}
	out, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return writeError(stderr, "error: marshal run: %v\n", err)
	}
	_, _ = stdout.Write(out)
	_, _ = io.WriteString(stdout, "\n")
	if run.Status != "pass" {
		return 1
	}
	return 0
}

func verifyReasonDescriber(code string) (string, string, bool) {
	copy, err := demo.LoadReasonCopy(code)
	if err != nil {
		return "", "", false
	}
	detail := copy.Description
	if copy.Remediation != "" {
		detail = strings.TrimSpace(detail + "\nRemediation: " + copy.Remediation)
	}
	return copy.Title, detail, true
}

func explainUsage() string {
	return strings.Join([]string{
		"Usage: intentproof-verify explain <bundle.proof.tar.zst>",
		"",
		"Human-readable bundle integrity and policy replay summary.",
	}, "\n")
}

func replayUsage() string {
	return strings.Join([]string{
		"Usage: intentproof-verify replay <bundle.proof.tar.zst>",
		"",
		"Re-run policy evaluation after integrity checks; JSON run on stdout.",
	}, "\n")
}

func verifyUsage() string {
	return strings.Join([]string{
		"Usage: intentproof-verify [--output <path>] <flow.json> <policy.json> <attestations.jsonl>",
		"       intentproof-verify <bundle.proof.tar.zst>",
		"       intentproof-verify explain <bundle.proof.tar.zst>",
		"       intentproof-verify replay <bundle.proof.tar.zst>",
		"",
		"Counterparty playbook: https://github.com/IntentProof/intentproof-tools/blob/main/docs/counterparty-verification.md",
		"Golden bundle: https://github.com/IntentProof/intentproof-spec/tree/main/golden/counterparty",
	}, "\n")
}

func readInputFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	return data, nil
}
