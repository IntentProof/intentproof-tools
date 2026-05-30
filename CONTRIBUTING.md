# Contributing to intentproof-tools

Thanks for your interest in IntentProof.

## Issues welcome

Please report bugs, verifier regressions, and conformance gaps via
[GitHub Issues](https://github.com/IntentProof/intentproof-tools/issues).
That is the primary way to help right now.

We do **not** accept unsolicited pull requests from outside the
maintainer team. If you are a customer or partner with a change that
must land upstream, contact IntentProof, Inc. before opening a PR.

## Trademark

"IntentProof" and "Verified by IntentProof" are trademarks of
IntentProof, Inc. Apache 2.0 grants you a copyright license; it does
not grant you a trademark license. See [`TRADEMARK.md`](TRADEMARK.md).

## Code style

- Determinism over cleverness. The verifier is the audit contract.
  In Go: sort map keys before iterating, use `time.UTC` and
  `RFC3339Nano`, never use `math/rand` in the verifier.
- Tests first. The product is a verification engine; testing is the
  core deliverable.
- No imports of `github.com/intentproof/intentproof-core/...` are
  permitted in this repository. CI rejects them via
  `scripts/check-tier-isolation.sh`. The invariant exists so this
  audit-contract surface remains Apache 2.0 and independently
  buildable, even when the operational data plane evolves.

## Release signing

Maintainer release workflows use `.github/workflows/release-build-sign.yml`
as the reusable signing contract for binaries, containers, npm packages,
PyPI packages, and generic release artifacts. The workflow requires GitHub
OIDC (`id-token: write`) for Sigstore keyless signing and fails closed when
Rekor publication is requested without an OIDC token.

See `docs/release-signing.md` for caller inputs and verification commands.

## License

By contributing as a maintainer, you agree your commits are licensed
under the Apache License 2.0 (see `LICENSE`).
