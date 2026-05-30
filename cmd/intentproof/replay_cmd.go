package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/intentproof/intentproof-tools/pkg/bundle"
)

func runReplay(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		writeUsage(stderr, replayUsage())
		return 1
	}
	if len(args) < 1 {
		writeUsage(stderr, replayUsage())
		return 1
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "read bundle: %v\n", err)
		return 1
	}
	b, err := bundle.Read(bytes.NewReader(raw))
	if err != nil {
		fmt.Fprintf(stderr, "read bundle: %v\n", err)
		return 1
	}
	vr, err := bundle.VerifyBundle(b, nil)
	if err != nil {
		fmt.Fprintf(stderr, "verify bundle: %v\n", err)
		return 1
	}
	if vr.Status != "pass" {
		fmt.Fprintf(stderr, "bundle integrity failed: %s\n", vr.Reason)
		return 1
	}
	run, err := bundle.ReplayPolicy(b)
	if err != nil {
		fmt.Fprintf(stderr, "policy replay: %v\n", err)
		return 1
	}
	out, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "marshal run: %v\n", err)
		return 1
	}
	_, _ = stdout.Write(out)
	_, _ = io.WriteString(stdout, "\n")
	if run.Status != "pass" {
		return 1
	}
	return 0
}

func replayUsage() string {
	return strings.Join([]string{
		"Usage: intentproof replay <bundle.proof.tar.zst>",
		"",
		"Re-run policy evaluation from bundle contents after integrity checks.",
		"Writes a fresh verification run as JSON on stdout.",
	}, "\n")
}
