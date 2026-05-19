package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/openpgpkms"
	"github.com/ProtonMail/go-crypto/openpgp"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		writeUsage(stderr)
		return 1
	}
	switch args[0] {
	case "sign":
		return runSign(args[1:], stdout, stderr)
	case "clearsign":
		return runClearSign(args[1:], stdout, stderr)
	case "export-public-key":
		return runExportPublicKey(args[1:], stdout, stderr)
	case "verify-apt-metadata":
		return runVerifyAptMetadata(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Unknown command: %s\n", args[0])
		writeUsage(stderr)
		return 1
	}
}

func runSign(args []string, stdout io.Writer, stderr io.Writer) int {
	opts := commandOptions{}
	fs := newFlagSet("intentproof-pkg-sign sign", stderr, &opts)
	var outputPath string
	fs.StringVar(&outputPath, "output", "", "write armored detached signature to this path")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "error: exactly one input file is required")
		return 1
	}

	entity, createdAt, err := entityFromOptions(opts)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	input, err := os.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "error: open input: %v\n", err)
		return 1
	}
	defer input.Close()

	out, closeOut, err := outputWriter(outputPath, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if closeOut != nil {
		defer closeOut()
	}
	if err := openpgpkms.ArmoredDetachSign(out, entity, input, createdAt); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func runClearSign(args []string, stdout io.Writer, stderr io.Writer) int {
	opts := commandOptions{}
	fs := newFlagSet("intentproof-pkg-sign clearsign", stderr, &opts)
	var outputPath string
	fs.StringVar(&outputPath, "output", "", "write armored clearsigned message to this path")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "error: exactly one input file is required")
		return 1
	}

	entity, createdAt, err := entityFromOptions(opts)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	input, err := os.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "error: open input: %v\n", err)
		return 1
	}
	defer input.Close()

	out, closeOut, err := outputWriter(outputPath, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if closeOut != nil {
		defer closeOut()
	}
	if err := openpgpkms.ArmoredClearSign(out, entity, input, createdAt); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func runExportPublicKey(args []string, stdout io.Writer, stderr io.Writer) int {
	opts := commandOptions{}
	fs := newFlagSet("intentproof-pkg-sign export-public-key", stderr, &opts)
	var outputPath string
	fs.StringVar(&outputPath, "output", "", "write armored public key to this path")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "error: export-public-key does not accept positional arguments")
		return 1
	}

	entity, _, err := entityFromOptions(opts)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	out, closeOut, err := outputWriter(outputPath, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if closeOut != nil {
		defer closeOut()
	}
	if err := openpgpkms.ArmoredPublicKey(out, entity); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if shouldPrintExportMessage(outputPath) {
		fmt.Fprintf(stdout, "exported OpenPGP public key %s\n", openpgpkms.Fingerprint(entity))
	}
	return 0
}

func runVerifyAptMetadata(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("intentproof-pkg-sign verify-apt-metadata", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var publicKeyPath string
	var releasePath string
	var releaseSigPath string
	var inreleasePath string
	fs.StringVar(&publicKeyPath, "public-key", "", "exported OpenPGP public key")
	fs.StringVar(&releasePath, "release", "", "path to Release file")
	fs.StringVar(&releaseSigPath, "release-sig", "", "path to Release.gpg")
	fs.StringVar(&inreleasePath, "inrelease", "", "path to InRelease")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if strings.TrimSpace(publicKeyPath) == "" || strings.TrimSpace(releasePath) == "" ||
		strings.TrimSpace(releaseSigPath) == "" || strings.TrimSpace(inreleasePath) == "" {
		fmt.Fprintln(stderr, "error: --public-key, --release, --release-sig, and --inrelease are required")
		return 1
	}
	if err := openpgpkms.VerifyAptMetadataFiles(publicKeyPath, releasePath, releaseSigPath, inreleasePath); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "PASS: verified apt metadata signatures")
	return 0
}

type commandOptions struct {
	keyID     string
	name      string
	comment   string
	email     string
	createdAt string
}

func newFlagSet(name string, stderr io.Writer, opts *commandOptions) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.keyID, "kms-key-id", "", "AWS KMS key ID or ARN (or INTENTPROOF_PKG_SIGN_KMS_KEY_ID)")
	fs.StringVar(&opts.name, "identity-name", openpgpkms.DefaultName, "OpenPGP user ID name")
	fs.StringVar(&opts.comment, "identity-comment", "", "OpenPGP user ID comment")
	fs.StringVar(&opts.email, "identity-email", openpgpkms.DefaultEmail, "OpenPGP user ID email")
	fs.StringVar(&opts.createdAt, "created-at", "", "stable OpenPGP key creation time as RFC3339 (or INTENTPROOF_PKG_SIGN_CREATED_AT)")
	return fs
}

func entityFromOptions(opts commandOptions) (*openpgp.Entity, time.Time, error) {
	createdAtRaw := strings.TrimSpace(opts.createdAt)
	if createdAtRaw == "" {
		createdAtRaw = strings.TrimSpace(os.Getenv("INTENTPROOF_PKG_SIGN_CREATED_AT"))
	}
	if createdAtRaw == "" {
		return nil, time.Time{}, fmt.Errorf("--created-at or INTENTPROOF_PKG_SIGN_CREATED_AT is required for a stable OpenPGP fingerprint")
	}
	createdAt, err := time.Parse(time.RFC3339, createdAtRaw)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse --created-at: %w", err)
	}
	createdAt = createdAt.UTC()
	keyID := strings.TrimSpace(opts.keyID)
	if keyID == "" {
		keyID = strings.TrimSpace(os.Getenv("INTENTPROOF_PKG_SIGN_KMS_KEY_ID"))
	}
	if keyID == "" {
		return nil, time.Time{}, fmt.Errorf("--kms-key-id or INTENTPROOF_PKG_SIGN_KMS_KEY_ID is required")
	}
	signer, err := openpgpkms.NewKMSSigner(context.Background(), keyID)
	if err != nil {
		return nil, time.Time{}, err
	}
	entity, err := openpgpkms.NewEntity(signer, openpgpkms.EntityOptions{
		Name:      opts.name,
		Comment:   opts.comment,
		Email:     opts.email,
		CreatedAt: createdAt,
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	return entity, createdAt, nil
}

func outputWriter(path string, stdout io.Writer) (io.Writer, func(), error) {
	path = strings.TrimSpace(path)
	if path == "" || path == "-" {
		return stdout, nil, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("open output: %w", err)
	}
	return f, func() { _ = f.Close() }, nil
}

func shouldPrintExportMessage(path string) bool {
	path = strings.TrimSpace(path)
	return path != "" && path != "-"
}

func writeUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "Usage: intentproof-pkg-sign <command>")
	fmt.Fprintln(stderr, "Commands:")
	fmt.Fprintln(stderr, "  sign --kms-key-id <key> --created-at <rfc3339> --output <file.asc> <file>")
	fmt.Fprintln(stderr, "  clearsign --kms-key-id <key> --created-at <rfc3339> --output <file> <file>")
	fmt.Fprintln(stderr, "  export-public-key --kms-key-id <key> --created-at <rfc3339> --output <key.asc>")
	fmt.Fprintln(stderr, "  verify-apt-metadata --public-key <key> --release <file> --release-sig <file> --inrelease <file>")
}
