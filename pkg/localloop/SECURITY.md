# Local loop security

`intentproof local` is a **developer-only** helper. It binds services to
loopback, stores data under `~/.intentproof/local`, and is not a production
deployment pattern.

Do not expose local ingest ports to untrusted networks. Delete
`~/.intentproof/local` to reset state.

For production-style verification, use offline `intentproof-verify` on proof
bundles — no running service required.
