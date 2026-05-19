package main

import (
	"fmt"
	"io"
	"os"

	"github.com/intentproof/intentproof-tools/pkg/initdetect"
)

func runInit(args []string, stdout io.Writer, stderr io.Writer) int {
	template := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--template":
			if i+1 >= len(args) || args[i+1] == "" {
				fmt.Fprintln(stderr, "--template requires a value")
				return 1
			}
			template = args[i+1]
			i++
		case "--help", "-h":
			fmt.Fprintln(stderr, "Usage: intentproof init [--template stripe-refund]")
			return 1
		default:
			fmt.Fprintf(stderr, "unexpected argument: %s\n", args[i])
			fmt.Fprintln(stderr, "Usage: intentproof init [--template stripe-refund]")
			return 1
		}
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(stderr, "init failed: working directory: %v\n", err)
		return 1
	}
	project, err := initdetect.Detect(cwd)
	if err != nil {
		fmt.Fprintf(stderr, "init failed: %v\n", err)
		return 1
	}

	switch template {
	case "":
		_, _ = io.WriteString(stdout, initdetect.FormatReport(project))
		return 0
	case "stripe-refund":
		_, _ = io.WriteString(stdout, initdetect.FormatStripeRefundTemplate(project))
		return 0
	default:
		fmt.Fprintf(stderr, "unknown init template: %s\n", template)
		fmt.Fprintln(stderr, "Usage: intentproof init [--template stripe-refund]")
		return 1
	}
}
