# intentproof-tools

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

## What is in here

| Path | Purpose |
|------|---------|
| `cmd/intentproof-verify` | Pure-Go offline verifier. Takes a `.proof.tar.zst` bundle and prints pass/fail. |
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

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.

Issues welcome — see `CONTRIBUTING.md`. Maintainer commits use DCO
`Signed-off-by:` trailers.

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
