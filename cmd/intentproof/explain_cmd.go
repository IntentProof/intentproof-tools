package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/intentproof/intentproof-tools/pkg/bundle"
	"github.com/intentproof/intentproof-tools/pkg/demo"
)

func runExplain(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		writeUsage(stderr, explainUsage())
		return 1
	}
	if len(args) < 1 {
		writeUsage(stderr, explainUsage())
		return 1
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "read bundle: %v\n", err)
		return 1
	}
	text, code, err := bundle.ExplainFromReader(bytes.NewReader(raw), reasonDescriber)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
	}
	_, _ = io.WriteString(stdout, text)
	if err != nil && code == 0 {
		code = 1
	}
	return code
}

func reasonDescriber(code string) (string, string, bool) {
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
		"Usage: intentproof explain <bundle.proof.tar.zst>",
		"",
		"Human-readable bundle integrity and policy replay summary.",
		"Set INTENTPROOF_SPEC_DIR for signed reason-catalog copy.",
	}, "\n")
}
