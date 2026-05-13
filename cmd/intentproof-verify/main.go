package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/intentproof/intentproof-tools/pkg/verifier"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 3 {
		fmt.Fprintln(stderr, "Usage: intentproof-verify <flow.json> <policy.json> <attestations.jsonl>")
		return 1
	}

	flowData, err := readInputFile(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	policyData, err := readInputFile(args[1])
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	attestationsData, err := readInputFile(args[2])
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	run, err := verifier.Verify(flowData, policyData, attestationsData)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "Run Status: %s\n", run.Status)
	return 0
}

func readInputFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	return data, nil
}
