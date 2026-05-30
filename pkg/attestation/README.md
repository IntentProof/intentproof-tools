# pkg/attestation

Public adapter interface, canonicalization helpers, replay-key conventions,
and signature primitives for third-party attestation adapters.

This package is part of the MIT-licensed verifier surface. Adapter
implementations belong in separate repositories or your own codebase; they
must not pull in retired hosted-service modules.

## Status

The interface is evolving with the v0.1 local contract. See
`docs/v0.1-local-contract.md` for the supported verification path today.
