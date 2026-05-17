# `intentproof-local` Container Image

`ghcr.io/intentproof/intentproof-local` packages the `intentproof local`
command as a minimal scratch-based image. It is intended for laptop and
self-host smoke tests that need the local ingest, verifier, and dashboard
services without installing the CLI directly.

## Published Tags

Release images publish these tags:

- `ghcr.io/intentproof/intentproof-local:<semver>`
- `ghcr.io/intentproof/intentproof-local:<semver>-<sha>`
- `ghcr.io/intentproof/intentproof-local:sha-<short>`

The image does not publish `latest`. Pin a release tag or digest.

## Runtime Ports

Expose the local-loop ports when running the image:

```bash
docker run --rm \
  -p 9787:9787 \
  -p 9788:9788 \
  -p 9789:9789 \
  ghcr.io/intentproof/intentproof-local:<tag>
```

- `9787`: local ingest API
- `9788`: local verifier endpoint
- `9789`: local dashboard

## Persistent State

The local loop stores state at `/home/nonroot/.intentproof/local` inside the
container. Mount that path to persist the SQLite database and embedded NATS
state across runs:

```bash
docker run --rm \
  -p 9787:9787 \
  -p 9788:9788 \
  -p 9789:9789 \
  -v intentproof-local:/home/nonroot/.intentproof/local \
  ghcr.io/intentproof/intentproof-local:<tag>
```

The container sets `INTENTPROOF_LOCAL_OPEN_BROWSER=0` because browser launch is
not meaningful inside the image.

## Verification

Images are signed by the release workflow after the multi-arch manifest is
pushed to GHCR. Verify a digest before pulling it into a controlled
environment:

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/IntentProof/intentproof-tools/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/intentproof/intentproof-local@sha256:<digest>
```
