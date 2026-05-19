# Local loop ingest security

The local ingest HTTP server (`IngestServer`, default `:9787`) is intended for
development on `127.0.0.1` only.

- It does **not** authenticate tenants with bearer tokens. Event authenticity
  relies on Ed25519 signatures registered in the local SDK registry.
- Do **not** bind the ingest port to `0.0.0.0` or expose it on an untrusted
  network without a firewall. Any client that can reach the port may submit
  events; only signature verification limits forgery for known SDK keys.

For hosted ingest, use the core `ingest` service with bearer or mTLS auth.
