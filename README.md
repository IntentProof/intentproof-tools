# intentproof-tools

[![CI](https://github.com/IntentProof/intentproof-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/IntentProof/intentproof-tools/actions/workflows/ci.yml)

The Apache 2.0 "audit contract" surface of IntentProof: the offline
verifier, developer CLI, policy compiler, bundle format, and crypto
primitives that any customer, regulator, or competitor must be able
to run forever without asking permission.

This repository is the Tier 1 audit-contract surface of IntentProof.
The Tier 1 / Tier 2 / Tier 3 split, the BSL-1.1-with-4-year-Apache
conversion of `intentproof-core`, and the no-Tier-1-imports-Tier-2
dependency invariant are normative for this repository:

- Tier 1 code (this repo) is Apache 2.0 and must remain depend-
  able by anyone, forever, without permission.
- Tier 2 code (`intentproof-core`) is BSL 1.1 today and converts
  to Apache 2.0 on a 4-year cadence.
- Tier 1 packages here MUST NOT import any
  `github.com/intentproof/intentproof-core/...` package. CI
  enforces this; see `scripts/check-tier-isolation.sh`.

## Who uses this

Integrators, auditors, regulators, and self-hosters who need the offline
verifier, developer CLI, policy compiler, and bundle format without
depending on the hosted data plane.

## What is in here

| Path | Purpose |
|------|---------|
| `cmd/intentproof-verify` | Pure-Go offline verifier. Takes a `.proof.tar.zst` bundle and prints pass/fail. See [`docs/counterparty-verification.md`](docs/counterparty-verification.md). |
| `cmd/intentproof` | Developer CLI. `policy lint`, `policy test`, `policy diff`, `policy publish`, `policy activate`, `local`. |
| `cmd/intentproof-pkg-sign` | KMS-backed OpenPGP signing helper for package repository metadata. |
| `pkg/verifier` | Deterministic DSL evaluator for the 7 canonical rule kinds. |
| `pkg/bundle` | `.proof.tar.zst` build / extract / signature-verify. |
| `pkg/policy` | YAML → canonical-JSON policy compiler, fingerprinting, semantic diff. |
| `pkg/crypto` | Policy signer / verifier abstractions, KMS + local-Ed25519 implementations. |
| `pkg/openpgpkms` | OpenPGP public-key export and detached-signature helpers backed by AWS KMS RSA signing keys. |
| `pkg/attestation` | Adapter SDK interface, canonicalization helpers, replay-key conventions. (First-party adapter *implementations* are Tier 2 and live in `intentproof-core`.) |

## What is NOT in here

The operational data plane — ingest API, outbox publisher, flow
builder, attestation gateway, query API, certificate issuer,
subject-mapping sweeper, pull-source workers, DB migrations — lives
in `intentproof-core` under BSL 1.1.

## Install

- macOS (Homebrew): `brew tap IntentProof/tap && brew install intentproof intentproof-verify`
- GitHub Release binaries: see [`docs/counterparty-verification.md`](docs/counterparty-verification.md)
- Local loop container: [`docs/intentproof-local-image.md`](docs/intentproof-local-image.md)

## Verify

Verify release artifacts with Cosign before install. Counterparty bundle
verification uses `intentproof-verify` — see
[`docs/counterparty-verification.md`](docs/counterparty-verification.md).

## Test

```bash
go build ./...
go test ./...
```

CI runs tier-isolation checks, coverage gates, and conformance fixtures.

## Release

Maintainer releases use Sigstore keyless signing via
[`.github/workflows/release-build-sign.yml`](.github/workflows/release-build-sign.yml).
See [`docs/release-signing.md`](docs/release-signing.md).

## Documentation hub

Per-repo README files plus
[`intentproof-infra`](https://github.com/IntentProof/intentproof-infra) for
self-host install and image verification. Docs site deferred — see
[`docs-hub-decision.md`](https://github.com/IntentProof/intentproof-infra/blob/main/docs/docs-hub-decision.md).

## Support

Report bugs and verifier regressions via
[GitHub Issues](https://github.com/IntentProof/intentproof-tools/issues).
See [`CONTRIBUTING.md`](CONTRIBUTING.md). Security reports:
[`SECURITY.md`](SECURITY.md).

## Local filesystem state

`intentproof local` stores its laptop-only runtime state under
`~/.intentproof/local`. That directory contains the local SQLite database
(`local.db`) and embedded NATS state used by the local loop. Delete
`~/.intentproof/local` to reset the local loop.

When present, `intentproof local` also imports the Node SDK public key from
`~/.intentproof/sdk-node/keypair.json` so locally wrapped events can verify
without extra setup. The local loop does not create that SDK keypair; the Node
SDK creates it when an app calls `configure()` without an explicit `dataDir`.

Tests and demos may override the home directory they use, so they do not need
to touch the real `~/.intentproof` tree.

The same local loop is also packaged as
`ghcr.io/intentproof/intentproof-local`; see
[`docs/intentproof-local-image.md`](docs/intentproof-local-image.md) for ports,
volume mounts, image tags, and signature verification.

## Local development

`intentproof-core` depends on this repository through a Go module
replace directive (`replace github.com/intentproof/intentproof-tools
=> ../intentproof-tools`) so the two repositories can be developed
together as siblings under a single workspace directory. A root
`go.work` file is the supported way to build them together:

```
your-workspace/
├── go.work
├── intentproof-tools/   # this repo (Apache 2.0)
└── intentproof-core/    # BSL 1.1
```

Build & test everything:

```
go build ./...
go test ./...
```

## License

Apache License 2.0 — see [`LICENSE`](LICENSE), [`NOTICE`](NOTICE), and
[`TRADEMARK.md`](TRADEMARK.md).
