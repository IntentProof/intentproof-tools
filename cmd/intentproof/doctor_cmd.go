package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/doctor"
)

func runDoctor(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "Usage: intentproof doctor")
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	report := doctor.Run(ctx, doctor.Options{})
	_, _ = io.WriteString(stdout, doctor.FormatReport(report))
	if report.HasFailures() {
		return 1
	}
	return 0
}
