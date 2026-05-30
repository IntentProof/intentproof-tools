# Command Drift Guardrails

This document captures behavior-level invariants that refactors should preserve
for verifier and developer CLI commands in this repository.

## cmd/intentproof

- Unknown top-level command returns exit code `1` and prints `Unknown command: <name>` to stderr.
- `intentproof doctor` with extra arguments returns exit code `1` and prints
  `Usage: intentproof doctor [--agent]` to stderr.
- `intentproof doctor` exits `1` when any check has status fail; exits `0` when
  checks are ok, warn, or skip only.
- `intentproof doctor --agent` (or `INTENTPROOF_AGENT=1`) prints markdown for
  coding agents.
- `intentproof init` performs offline, read-only project detection and prints
  `Detected`, `Recommended setup`, and `Next` sections.
- `intentproof init --template stripe-refund` prints the preview wedge outline
  and does not claim live Stripe end-to-end readiness before reconciliation
  gates close.
- `intentproof init --agent` (or `INTENTPROOF_AGENT=1`) prints markdown for
  coding agents; `--template stripe-refund --agent` includes the Path 3 outline.
- Missing policy subcommand returns exit code `1` and prints `Usage: intentproof policy <subcommand>`.
- `policy test` fixture output order is deterministic and alphabetical by fixture directory name.

## cmd/intentproof-verify

- Missing arguments return exit code `1` and print usage to stderr.
- `--help` / `-h` / `help` return exit code `1`, print usage plus counterparty
  playbook and golden-bundle URLs to stderr.
- Missing input files return exit code `1` with `error: read <file>: ...` on stderr.
- Golden counterparty bundle stdout SHA-256 must match
  `intentproof-spec/golden/counterparty/expected-verify-stdout-sha256.txt`
  (`TestGoldenCounterpartyVerifyStdout`).

## cmd/intentproof verify

- Missing arguments or `--help` return exit code `1` and print usage with
  counterparty playbook and golden-bundle URLs to stderr.
