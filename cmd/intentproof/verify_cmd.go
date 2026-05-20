package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/intentproof/intentproof-tools/pkg/bundle"
)

var verifyCmdJSONMarshalIndent = json.MarshalIndent

func runVerify(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		writeUsage(stderr, "Usage: intentproof verify <bundle.proof.tar.zst>")
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
