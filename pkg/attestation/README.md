# pkg/attestation

The adapter SDK interface for IntentProof's reconciliation tier.

This package holds **only** the public interface, canonicalization
helpers, replay-key conventions, and signature primitives that allow
third-party and community adapters to be built. It is Apache 2.0 by
design: the contract that an adapter must satisfy must be inspectable
and re-implementable forever.

**First-party adapter implementations** (`stripe@webhook`,
`github@webhook`, `pagerduty@webhook`, `okta@event-hook`,
`linear@webhook`, `jira@webhook`, `anthropic-eval@webhook`,
`openai-eval@webhook`, `aws-eventbridge@events`,
`salesforce@event-bus`, `generic-ed25519@webhook`,
`generic-hmac@webhook`, and future ones) live in `intentproof-core`
under BSL 1.1. They are not part of the Apache surface and must not
be imported from here.

## Status

Placeholder. The current `SourceAdapter` interface and Stripe adapter
implementation live in `intentproof-core/cmd/attestation-gw`. The
interface-only extraction into this package is tracked alongside the
adapter conformance harness work and a later licensing-split
cleanup pass.
