package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/doctor"
)

func runDoctor(args []string, stdout io.Writer, stderr io.Writer) int {
	agent := doctorAgentOutputEnabled(args)
	for _, arg := range args {
		switch arg {
		case "--agent":
			continue
		case "--help", "-h":
			fmt.Fprintln(stderr, doctorUsage())
			return 1
		default:
			fmt.Fprintf(stderr, "unexpected argument: %s\n", arg)
			fmt.Fprintln(stderr, doctorUsage())
			return 1
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	report := doctor.Run(ctx, doctor.Options{})
	if agent {
		_, _ = io.WriteString(stdout, doctor.FormatAgentMarkdown(report))
	} else {
		_, _ = io.WriteString(stdout, doctor.FormatReport(report))
	}
	if report.HasFailures() {
		return 1
	}
	return 0
}

func doctorUsage() string {
	return "Usage: intentproof doctor [--agent]"
}

func doctorAgentOutputEnabled(args []string) bool {
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
