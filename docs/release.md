# v0.1.0 release flow

Release automation is tag-driven: bump the version in the repo, merge, tag
`v*`, then CI publishes artifacts.

## intentproof-tools (binaries + Homebrew)

1. Ensure `main` passes CI and `SPEC_REF` matches the spec tuple.
2. Tag on `intentproof-tools`:

   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

3. Workflows (see [`release-signing.md`](release-signing.md)):
   - `release-binaries.yml` — GoReleaser archives on GitHub Releases
   - `release-homebrew.yml` — bumps `IntentProof/homebrew-tap` when the release
     is published (requires `INTENTPROOF_HOMEBREW_TAP_TOKEN`)

Dry-run binaries without publishing:

```bash
gh workflow run release-binaries.yml -f release_ref=refs/heads/main
```

## intentproof-spec

1. Tag `v0.1.0` on `intentproof-spec` after `npm test` passes on `main`.
2. `release-spec.yml` regenerates the integrity manifest, Cosign-signs it, and
   uploads the spec release bundle (requires `SPEC_INTEGRITY_PRIVATE_KEY`).

## SDK registries

| Repo | Registry | Workflow | Version file |
|------|----------|----------|--------------|
| `intentproof-sdk-node` | npm | `release-npm.yml` | `package.json` |
| `intentproof-sdk-python` | PyPI | `release-pypi.yml` | `pyproject.toml` |
| `intentproof-sdk-go` | Go module (tag) | `release-go.yml` | tag only |

Tag ref must match the package version (`v` + SemVer). Release jobs run the
same conformance tests as CI (pinned spec via `intentproof-tools` `SPEC_REF`).

npm and PyPI publish use OIDC trusted publishers; configure registry tokens only
for dry-runs that opt into legacy auth.

## Order for a coordinated `v0.1.0` tuple

1. Spec tag (if the integrity manifest or schemas changed).
2. Tools tag (verifier binaries + tap bump).
3. SDK tags (npm / PyPI / Go module tag).

Update spec `pins.v1.json` / matrix when normative spec content or SDK SHAs move.
