# OSS-Fuzz upstream contribution

Production copy of `google/oss-fuzz/projects/intentproof/`. Open a pull
request against [google/oss-fuzz](https://github.com/google/oss-fuzz) with
these files.

## Layout

| Path | Purpose |
|------|---------|
| `project.yaml` | Project metadata and contacts |
| `Dockerfile` | Builder image cloning tools, spec, and core at pinned refs |
| `build.sh` | Native Go fuzz targets and spec seed corpus archives |
| `pins.env` | Pin manifest (mirrored in Dockerfile `ENV`) |

## Fuzz targets

| Binary | Package | Spec corpus |
|--------|---------|-------------|
| `fuzz_marshal_raw` | `intentproof-tools/pkg/canon` | `canon/` |
| `fuzz_verify` | `intentproof-tools/pkg/verifier` | inline seeds only |
| `fuzz_bundle_verify` | `intentproof-tools/pkg/bundle` | `bundle/` |
| `fuzz_compile` | `intentproof-tools/pkg/policy` | `policy/` |
| `fuzz_parse_execution_event` | `intentproof-core/pkg/ingest` | `ingest/` |

Golden corpora live in `intentproof-spec/golden/fuzz-corpora/`. Bump
`pins.env` and Dockerfile `ENV` when surfaces change.

## File upstream PR

From the repository root:

```bash
bash ./scripts/prepare-oss-fuzz-upstream.sh /path/to/oss-fuzz-clone
cd /path/to/oss-fuzz-clone
git switch -c add-intentproof
git add projects/intentproof
git commit -s -m "Add IntentProof platform fuzz project"
git push -u origin add-intentproof
gh pr create --repo google/oss-fuzz --title "Add IntentProof" --body "..."
```

Sign the [Google CLA](https://cla.developers.google.com/) before opening the
upstream PR.

## Local dry run

After cloning [google/oss-fuzz](https://github.com/google/oss-fuzz):

```bash
bash ./scripts/prepare-oss-fuzz-upstream.sh ../oss-fuzz
cd ../oss-fuzz
python3 infra/helper.py build_image intentproof
python3 infra/helper.py build_fuzzers intentproof
python3 infra/helper.py check_build intentproof
```

Use [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) for CI-style
runs without the full OSS-Fuzz checkout.
