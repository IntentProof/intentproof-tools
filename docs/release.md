# Release flow (tag → registry)

Release automation is tag-driven: set the version in each repo, merge, push a
`v*` tag that matches that version, then CI publishes artifacts.

**Contract milestone** names (for example the v0.1 local verifier contract in
`docs/v0.1-local-contract.md`) describe the *spec/tools behavior freeze*, not
the SemVer on every package. Package versions below are what registries and tags
use today.

## Current package versions (2026-05)

| Repo | Version source | Published as |
|------|----------------|--------------|
| `intentproof-tools` | Git tag only | GitHub Release archives (`intentproof`, `intentproof-verify`) |
| `intentproof-spec` | `package.json` `1.0.0` | GitHub Release spec bundle + signed manifest |
| `intentproof-sdk-node` | `package.json` `0.2.0` | npm `@intentproof/sdk` |
| `intentproof-sdk-python` | `pyproject.toml` `0.1.0` | PyPI `intentproof` |
| `intentproof-sdk-go` | Git tag only | Go module via proxy |
| `homebrew-tap` | Formula `version` field | Manual bump after tools release |

Matrix `*_version` labels in `intentproof-spec` are tuple bookkeeping strings;
they may differ from registry SemVer until you align them on a release bump.

## intentproof-tools (binaries)

1. Ensure `main` passes CI and `SPEC_REF` matches the spec tuple.
2. Tag with the verifier release SemVer (example first stable: `v0.2.0` if that
   is the chosen tools line — not necessarily `v0.1.0`):

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

3. `release-binaries.yml` runs GoReleaser and Cosign signing (see
   [`release-signing.md`](release-signing.md)).

Dry-run without publishing a GitHub Release:

```bash
gh workflow run release-binaries.yml -f release_ref=refs/heads/main
```

### Homebrew tap (manual, no tools repo secret)

Automated tap PRs previously used `INTENTPROOF_HOMEBREW_TAP_TOKEN`; that is
**not** part of the restored slim pipeline. After a tools GitHub Release exists:

1. In `homebrew-tap`, run (or adapt) the renderer from a tools checkout:

   ```bash
   gh release view v0.2.0 --repo IntentProof/intentproof-tools --json assets > /tmp/assets.json
   python3 scripts/render-homebrew-formulas.py \
     --release-tag v0.2.0 \
     --assets-json /tmp/assets.json \
     --output-dir Formula
   ```

2. Open a PR on `IntentProof/homebrew-tap` with the formula changes.

## intentproof-spec

Tag must match `package.json` (currently `1.0.0` → `v1.0.0`):

```bash
git tag v1.0.0 && git push origin v1.0.0
```

`release-spec.yml` needs `SPEC_INTEGRITY_PRIVATE_KEY` for manifest signing on
tag releases.

## SDK registries

| Repo | Tag example | Workflow |
|------|-------------|----------|
| `intentproof-sdk-node` | `v0.2.0` | `release-npm.yml` |
| `intentproof-sdk-python` | `v0.1.0` | `release-pypi.yml` |
| `intentproof-sdk-go` | `v0.2.0` (or chosen module tag) | `release-go.yml` |

Release jobs use the same conformance gates as CI (pinned spec via tools
`SPEC_REF`). The workflow syncs npm version from the tag on pack; PyPI uses the
version in `pyproject.toml` — ensure it matches the tag before pushing.

npm and PyPI use OIDC trusted publishers on tag pushes.

## Suggested first coordinated cut

1. Spec `v1.0.0` only if integrity manifest / schemas changed since last tuple.
2. Tools `v0.2.0` (or your chosen verifier SemVer) + manual Homebrew PR.
3. SDK tags matching each `package.json` / `pyproject.toml` / module tag.
4. Update `pins.v1.json` / matrix if normative spec content or SDK SHAs move.
