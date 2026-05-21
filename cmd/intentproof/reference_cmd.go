package main

import (
	"fmt"
	"io"
)

type referencePackManifest struct {
	ReferenceID    string `json:"reference_id"`
	Domain         string `json:"domain"`
	Name           string `json:"name"`
	Version        int    `json:"version"`
	DisplayName    string `json:"display_name"`
	Summary        string `json:"summary"`
	Policy         string `json:"policy"`
	PolicyYAML     string `json:"policy_yaml"`
	MigrationNotes string `json:"migration_notes"`
}

type referencePack struct {
	Manifest referencePackManifest
	Dir      string
}

func runReference(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "Usage: intentproof reference <subcommand>")
		return 1
	}

	switch args[0] {
	case "list":
		return runReferenceList(args[1:], stdout, stderr)
	case "fork":
		return runReferenceFork(args[1:], stdout, stderr)
	default:
		writeUnknownCommand(stderr, "reference command", args[0])
		return 1
	}
}
