# intentproof-tools

[![CI](https://github.com/IntentProof/intentproof-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/IntentProof/intentproof-tools/actions/workflows/ci.yml)

Offline verifier, developer CLI, policy compiler, bundle format, and crypto
primitives for IntentProof.

## Who uses this

Integrators, auditors, regulators, and self-hosters who need the offline
verifier, developer CLI, policy compiler, and bundle format without
depending on the hosted data plane.

## Scope

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
| `pkg/attestation` | Adapter SDK interface, canonicalization helpers, replay-key conventions. |

Hosted data-plane services (ingest, query API, certificate issuer, and
related workers) live in
[`intentproof-core`](https://github.com/IntentProof/intentproof-core).

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

CI runs tier-isolation checks, coverage gates, conformance fixtures, and
cross-repo ecosystem pin checks (see
[`intentproof-spec/compatibility/PINS.md`](https://github.com/IntentProof/intentproof-spec/blob/main/compatibility/PINS.md)).

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

## Local loop

`intentproof local` stores laptop-only runtime state under
`~/.intentproof/local` (SQLite + embedded NATS). Delete that directory to
reset the local loop.

When present, `intentproof local` imports the Node SDK public key from
`~/.intentproof/sdk-node/keypair.json` so locally wrapped events verify
without extra setup.

The same local loop ships as `ghcr.io/intentproof/intentproof-local`; see
[`docs/intentproof-local-image.md`](docs/intentproof-local-image.md) for ports,
volume mounts, image tags, and signature verification.

## Local development

Develop alongside `intentproof-core` using sibling checkouts and a root
`go.work` file:

```
your-workspace/
├── go.work
├── intentproof-tools/
└── intentproof-core/
```

## License

Apache License 2.0 — see [`LICENSE`](LICENSE), [`NOTICE`](NOTICE), and
[`TRADEMARK.md`](TRADEMARK.md).
