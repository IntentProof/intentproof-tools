# intentproof-tools

[![CI](https://github.com/IntentProof/intentproof-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/IntentProof/intentproof-tools/actions/workflows/ci.yml)

Offline verifier and developer CLI for IntentProof proof bundles.

## Commands

| Binary | Role |
|--------|------|
| `intentproof-verify` | Offline `verify`, `explain`, `replay` |
| `intentproof` | Demos, policy compile, bundle helpers, optional local dev loop |

Libraries live under `pkg/` (`verifier`, `bundle`, `policy`, `crypto`, and
related packages).

## Docs

- [v0.1 local contract](docs/v0.1-local-contract.md)
- [Counterparty verification](docs/counterparty-verification.md)
- [Offline refund walkthrough](docs/offline-refund-verify.md) (~10 minutes)

## Install

```bash
brew tap IntentProof/tap && brew install intentproof intentproof-verify
```

Release flow (`v*` tags, manual Homebrew tap): [release.md](docs/release.md).
Cosign verification:
[counterparty-verification.md](docs/counterparty-verification.md).

## Build and test

```bash
go build ./...
go test ./...
```

## Support

[GitHub Issues](https://github.com/IntentProof/intentproof-tools/issues) —
see [CONTRIBUTING.md](CONTRIBUTING.md). Security reports:
`security@intentproof.io` or a private GitHub Security Advisory.

## License

MIT — see [LICENSE](LICENSE).
