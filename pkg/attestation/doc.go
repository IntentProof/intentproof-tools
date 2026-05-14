// Package attestation defines the Tier 1 (Apache 2.0) contract that
// every source adapter feeding the IntentProof attestation gateway
// must satisfy.
//
// # Scope
//
// This package is intentionally minimal. It contains only:
//
//   - The [SourceAdapter] interface that an adapter must implement.
//   - The wire-shape types passed across that interface ([Result],
//     [SourceAdapter.SourceSignature]).
//   - Pure canonicalization helpers that derive the deterministic
//     bytes signed by the platform: [DeriveAttestationID],
//     [Subject], and [CanonicalBody].
//
// It does not contain any I/O, logging, metrics, persistence,
// transport, or first-party adapter implementations. Those live in
// the Tier 2 operational gateway in intentproof-core, which imports
// this package.
//
// # Audience
//
// Third-party and community adapter authors implement
// [SourceAdapter] against this package. The gateway then loads the
// adapter and invokes its methods for every inbound webhook or
// pull-mode event. Because this package is Apache 2.0, the contract
// is stable, inspectable, and re-implementable.
//
// # Boundary
//
// The gateway is the only legitimate caller of an adapter. An
// adapter:
//
//   - MUST be deterministic for [SourceAdapter.Canonicalize]: the
//     same body must always yield the same [Result].
//   - MUST be deterministic for [SourceAdapter.ReplayKey]: identical
//     inbound events must produce the same key so the gateway can
//     suppress replays.
//   - MUST validate authenticity in [SourceAdapter.Verify] before
//     the gateway trusts any other method's output.
//   - SHOULD perform no I/O. The gateway provides the
//     [context.Context]; adapters are expected to be CPU-bound and
//     fast.
//
// # Signing
//
// Adapters never sign attestations themselves. The gateway calls
// [CanonicalBody] with the adapter's [Result] and the platform's
// signing key produces the Ed25519 signature over
// sha256(canonical_body). This split keeps key material out of
// third-party code.
package attestation
