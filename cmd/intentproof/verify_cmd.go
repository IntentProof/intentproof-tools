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

var verifyCmdJSONMarshalIndent = json.MarshalIndent

func runVerify(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		writeUsage(stderr, "Usage: intentproof verify <bundle.proof.tar.zst>")
		_, _ = fmt.Fprintln(stderr, "Counterparty playbook: docs/counterparty-verification.md")
		_, _ = fmt.Fprintln(stderr, "Golden bundle: intentproof-spec/golden/counterparty/")
		return 0
	}
	if len(args) < 1 {
		writeUsage(stderr, verifyUsage())
		return 1
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		writeUsage(stderr, verifyUsage())
		return 1
	}
	path := args[0]
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(stderr, "read bundle: %v\n", err)
		return 1
	}
	vr, err := bundle.Verify(bytes.NewReader(raw), nil)
	if err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return 1
	}
	out, err := verifyCmdJSONMarshalIndent(vr, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "marshal result: %v\n", err)
		return 1
	}
	_, _ = stdout.Write(out)
	_, _ = io.WriteString(stdout, "\n")
	if vr.Status != "pass" {
		return 1
	}
	return 0
}

func verifyUsage() string {
	return strings.Join([]string{
		"Usage: intentproof verify <bundle.proof.tar.zst>",
		"",
		"Offline bundle verification (JSON stdout). For human-readable output",
		"and the third-party playbook, use intentproof-verify instead.",
		"",
		"Counterparty playbook: https://github.com/IntentProof/intentproof-tools/blob/main/docs/counterparty-verification.md",
		"Golden bundle: https://github.com/IntentProof/intentproof-spec/tree/main/golden/counterparty",
	}, "\n")
}
