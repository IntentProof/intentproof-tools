package main

import (
	"fmt"
	"io"

	"github.com/intentproof/intentproof-tools/pkg/policy"
)

func runPolicyDiff(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "Usage: intentproof policy diff <left.yaml> <right.yaml>")
		return 1
	}

	left, err := policy.CompileFile(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "compile left failed: %v\n", err)
		return 1
	}

	right, err := policy.CompileFile(args[1])
	if err != nil {
		fmt.Fprintf(stderr, "compile right failed: %v\n", err)
		return 1
	}

	diff := policy.Diff(left, right)
	fmt.Fprint(stdout, policy.FormatDiff(diff))

	if diff.Same {
		return 0
	}
	return 1
}
