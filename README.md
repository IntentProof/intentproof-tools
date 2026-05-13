# intentproof-tools

The Apache 2.0 "audit contract" surface of IntentProof: the offline
verifier, developer CLI, policy compiler, bundle format, and crypto
primitives that any customer, regulator, or competitor must be able
to run forever without asking permission.

This repository is governed by
[ADR-010 — Licensing and IP strategy](https://github.com/intentproof/plan-intentproof/blob/main/decisions/ADR-010-licensing-and-ip-strategy.md).
The Tier 1 / Tier 2 / Tier 3 split, the BSL-1.1-with-4-year-Apache
conversion of `intentproof-core`, and the no-Tier-1-imports-Tier-2
invariant all live there.

## What is in here

| Path | Purpose |
|------|---------|
| `cmd/intentproof-verify` | Pure-Go offline verifier. Takes a `.proof.tar.zst` bundle and prints pass/fail. |
| `cmd/intentproof` | Developer CLI. `policy lint`, `policy test`, `policy diff`, `policy publish`, `policy activate`, `local`. |
| `pkg/verifier` | Deterministic DSL evaluator for the 7 canonical rule kinds. |
| `pkg/bundle` | `.proof.tar.zst` build / extract / signature-verify. |
| `pkg/policy` | YAML → canonical-JSON policy compiler, fingerprinting, semantic diff. |
| `pkg/crypto` | Policy signer / verifier abstractions, KMS + local-Ed25519 implementations. |
| `pkg/attestation` | Adapter SDK interface, canonicalization helpers, replay-key conventions. (First-party adapter *implementations* are Tier 2 and live in `intentproof-core`.) |

## What is NOT in here

The operational data plane — ingest API, outbox publisher, flow
builder, attestation gateway, query API, certificate issuer,
subject-mapping sweeper, pull-source workers, DB migrations — lives
in `intentproof-core` under BSL 1.1.

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.

Contributions are accepted under the
[Developer Certificate of Origin](https://developercertificate.org/)
via `Signed-off-by:` trailers on every commit. See `CONTRIBUTING.md`.

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
