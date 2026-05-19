package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/intentproof/intentproof-tools/pkg/initdetect"
)

func runInit(args []string, stdout io.Writer, stderr io.Writer) int {
	template := ""
	agent := agentOutputEnabled(args)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--agent":
			continue
		case "--template":
			if i+1 >= len(args) || args[i+1] == "" {
				fmt.Fprintln(stderr, "--template requires a value")
				return 1
			}
			template = args[i+1]
			i++
		case "--help", "-h":
			fmt.Fprintln(stderr, initUsage())
			return 1
		default:
			fmt.Fprintf(stderr, "unexpected argument: %s\n", args[i])
			fmt.Fprintln(stderr, initUsage())
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

	if agent {
		switch template {
		case "":
			_, _ = io.WriteString(stdout, initdetect.FormatAgentMarkdown(project))
		case "stripe-refund":
			_, _ = io.WriteString(stdout, initdetect.FormatStripeRefundAgentMarkdown(project))
		default:
			fmt.Fprintf(stderr, "unknown init template: %s\n", template)
			fmt.Fprintln(stderr, initUsage())
			return 1
		}
		return 0
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
		fmt.Fprintln(stderr, initUsage())
		return 1
	}
}

func initUsage() string {
	return "Usage: intentproof init [--template stripe-refund] [--agent]"
}

func agentOutputEnabled(args []string) bool {
	if env := strings.TrimSpace(os.Getenv("INTENTPROOF_AGENT")); env != "" {
		switch strings.ToLower(env) {
		case "1", "true", "yes", "on":
			return true
		}
	}
	for _, arg := range args {
		if arg == "--agent" {
			return true
		}
	}
	return false
}
