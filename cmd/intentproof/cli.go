package main

import (
	"fmt"
	"io"

	"github.com/intentproof/intentproof-tools/pkg/buildinfo"
)

func writeUsage(stderr io.Writer, usage string) {
	fmt.Fprintln(stderr, usage)
}

func writeUnknownCommand(stderr io.Writer, label, cmd string) {
	fmt.Fprintf(stderr, "Unknown %s: %s\n", label, cmd)
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		writeUsage(stderr, "Usage: intentproof <command>\nCommands: demo, doctor, explain, init, local, policy, reference, replay, verify")
		return 1
	}

	switch args[0] {
	case "--version", "version":
		fmt.Fprintln(stdout, buildinfo.String("intentproof"))
		return 0
	case "demo":
		return runDemo(args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(args[1:], stdout, stderr)
	case "explain":
		return runExplain(args[1:], stdout, stderr)
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "local":
		if err := startLocalServer(); err != nil {
			fmt.Fprintf(stderr, "local server failed: %v\n", err)
			return 1
		}
		return 0
	case "policy":
		return runPolicy(args[1:], stdout, stderr)
	case "reference":
		return runReference(args[1:], stdout, stderr)
	case "replay":
		return runReplay(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	default:
		writeUnknownCommand(stderr, "command", args[0])
		return 1
	}
}

func runPolicy(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		writeUsage(stderr, "Usage: intentproof policy <subcommand>")
		return 1
	}
	switch args[0] {
	case "lint":
		return runPolicyLint(args[1:], stdout, stderr)
	case "test":
		return runPolicyTest(args[1:], stdout, stderr)
	case "publish":
		return runPolicyPublish(args[1:], stdout, stderr)
	case "activate":
		return runPolicyActivate(args[1:], stdout, stderr)
	case "diff":
		return runPolicyDiff(args[1:], stdout, stderr)
	default:
		writeUnknownCommand(stderr, "policy command", args[0])
		return 1
	}
}
