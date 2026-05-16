package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/intentproof/intentproof-tools/pkg/demo"
	"github.com/intentproof/intentproof-tools/pkg/localloop"
)

func runDemo(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		writeUsage(stderr, "Usage: intentproof demo <scenario>")
		return 1
	}
	switch args[0] {
	case "refund":
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "working directory: %v\n", err)
			return 1
		}
		if err := demo.RunRefund(context.Background(), demo.Options{
			Stdout:      stdout,
			Stderr:      stderr,
			WorkDir:     wd,
			OpenBrowser: localloop.LocalDashboardAutoOpenEnabled(),
		}); err != nil {
			fmt.Fprintf(stderr, "demo refund: %v\n", err)
			return 1
		}
		return 0
	default:
		writeUnknownCommand(stderr, "demo scenario", args[0])
		return 1
	}
}
