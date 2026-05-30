# Contributing to intentproof-tools

Thank you for helping improve IntentProof.

## How to help

We welcome [GitHub Issues](https://github.com/IntentProof/intentproof-tools/issues)
and pull requests — bug reports, docs, verifier fixes, and tests.

- **Small fixes:** open a PR with a short summary and how you tested it.
- **Larger changes:** open an issue first so we can align on scope before you
  invest a big diff.

## Pull requests

- Keep changes focused; one logical change per PR when possible.
- Run `go build ./...` and `go test ./...` before opening.
- Behavior changes need regression tests (the verifier is the product).
- Do not import `github.com/intentproof/intentproof-core/...` — CI enforces
  isolation via `scripts/check-tier-isolation.sh`.

## Code style

- Determinism in verifier paths: sorted map keys, UTC timestamps, no
  `math/rand` in verification logic.

## License

By contributing, you agree your contributions are licensed under the MIT
License (see `LICENSE`).
