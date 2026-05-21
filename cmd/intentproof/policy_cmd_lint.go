package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/intentproof/intentproof-tools/pkg/policy"
)

func runPolicyLint(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "Usage: intentproof policy lint <policy.yaml>")
		return 1
	}

	result, err := policy.CompileFile(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "lint failed: %v\n", err)
		return 1
	}

	parts := make([]string, 0, len(result.RuleCounts))
	for _, c := range result.RuleCounts {
		parts = append(parts, fmt.Sprintf("%s:%d", c.Category, c.Count))
	}

	fmt.Fprintln(stdout, "schema: OK")
	fmt.Fprintln(stdout, "semantic: OK")
	fmt.Fprintf(stdout, "rule count: %d (%s)\n", len(result.Policy.Rules), strings.Join(parts, ", "))
	fmt.Fprintf(stdout, "fingerprint: %s\n", result.Fingerprint)

	canonical, err := policyCmdJSONMarshalIndent(result.Policy, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "render canonical policy: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(canonical))

	return 0
}
