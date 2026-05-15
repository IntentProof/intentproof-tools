## Cursor Cloud specific instructions

### Repository layout

This is the Tier 1 audit-contract surface of IntentProof (Apache 2.0). It is developed as a sibling of `intentproof-core` via a shared `go.work` file at `/agent/repos/go.work`.

**Critical invariant:** This repo MUST NOT import `github.com/intentproof/intentproof-core/...`. CI enforces this via `scripts/check-tier-isolation.sh`.

### Running tests

- `go test ./...` — runs all unit tests.
- `scripts/check-tier-isolation.sh` — verifies no Tier 2 imports.
- `scripts/check-spec-conformance.sh` — checks conformance against `intentproof-spec` golden fixtures.

### Gotchas

- **Go 1.25.0 required.** Ensure `/usr/local/go/bin` is on `PATH`.
- **go.work file** at `/agent/repos/go.work` links this repo with `intentproof-core` for sibling development.
- **Policy testing**: `go run ./cmd/intentproof policy lint <path>` and `go run ./cmd/intentproof policy test <dir>` work standalone from this repo.
