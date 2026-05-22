# OSS-Fuzz upstream contribution

These files are the proposed `google/oss-fuzz/projects/intentproof/` project.
Copy them into an OSS-Fuzz fork and open a pull request against
[google/oss-fuzz](https://github.com/google/oss-fuzz).

## Layout

| Path | Purpose |
|------|---------|
| `project.yaml` | Project metadata and contacts |
| `Dockerfile` | Builder image cloning tools, spec, and core |
| `build.sh` | Registers Go fuzz targets and seed corpora via `INTENTPROOF_SPEC_DIR` |

## Fuzz targets

- `intentproof-tools/pkg/canon` — `FuzzMarshalRaw`
- `intentproof-tools/pkg/verifier` — `FuzzVerify`
- `intentproof-tools/pkg/bundle` — `FuzzBundleVerify`
- `intentproof-tools/pkg/policy` — `FuzzCompile`
- `intentproof-core/pkg/ingest` — `FuzzParseExecutionEvent`

Golden seed corpora live in `intentproof-spec/golden/fuzz-corpora/`. Pin
repository refs in the Dockerfile before filing upstream.

## Local dry run

Use [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) or the
OSS-Fuzz helper container after replacing shallow clones with pinned SHAs
matching `SPEC_REF` / `CORE_REF` in this repository.
