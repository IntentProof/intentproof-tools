package attestation

import (
	"context"
	"encoding/json"
	"time"
)

// Result is the normalized output of an adapter's Canonicalize step.
// It is the minimum information the gateway needs to derive an
// attestation ID, look up correlation, and produce the signed
// canonical body.
//
// All fields are required unless documented otherwise. The gateway
// rejects results that violate these constraints.
type Result struct {
	// SourceEventID is the event identifier assigned by the upstream
	// source (for example a webhook event id). It is used together
	// with the tenant and source id to derive a deterministic
	// attestation id; see [DeriveAttestationID].
	SourceEventID string

	// SourceEmittedAt is the timestamp the upstream source reports
	// for when the event was produced. Canonicalization normalizes
	// the value to UTC (preserving the instant but converting the
	// timezone offset) before placing it in the canonical body.
	SourceEmittedAt time.Time

	// SubjectType is the logical type of the object the attestation
	// is about, for example "stripe_refund" or "github_check_run".
	// Free-form but stable per adapter.
	SubjectType string

	// SubjectID is the upstream identifier of the subject object.
	// Used for correlation lookup.
	SubjectID string

	// Claim is the specific claim being attested, typically the
	// upstream event type (for example "refund.created" or
	// "charge.refunded").
	Claim string

	// ClaimValue is the JSON-encoded payload that supports the
	// claim. The gateway round-trips this into the canonical body
	// after decoding. It MUST be valid JSON; null is permitted.
	ClaimValue json.RawMessage
}

// SourceAdapter is the contract every source adapter implements. The
// gateway resolves the adapter for a given source identifier and
// invokes these methods in order for each inbound event:
//
//  1. [SourceAdapter.Verify]
//  2. [SourceAdapter.ReplayKey]
//  3. [SourceAdapter.Canonicalize]
//  4. [SourceAdapter.SourceSignature]
//
// Implementations MUST be safe for concurrent use; the gateway
// shares a single adapter instance across goroutines.
type SourceAdapter interface {
	// Verify checks that the request body is an authentic message
	// from the upstream source. The secret is the tenant- or
	// source-scoped credential the operator configured (for example
	// a webhook signing key). Headers are the lowercased HTTP
	// headers from the inbound request. Body is the raw request
	// body bytes; adapters MUST verify over the bytes received,
	// not over any re-marshalled form.
	//
	// A non-nil error means the message is not authentic and the
	// gateway MUST reject the request before invoking any other
	// method.
	Verify(ctx context.Context, secret string, headers map[string]string, body []byte) error

	// Canonicalize parses the verified body into the normalized
	// [Result] shape. It MUST be deterministic: the same body
	// always yields the same [Result]. It MUST NOT perform I/O.
	Canonicalize(ctx context.Context, body []byte) (Result, error)

	// ReplayKey returns a stable, opaque identifier for the inbound
	// event used by the gateway to suppress duplicates. Two
	// requests that represent the same upstream event MUST produce
	// the same key. When the upstream source provides a usable
	// event id, adapters SHOULD return it directly; otherwise a
	// hash of the canonical body is acceptable.
	ReplayKey(ctx context.Context, headers map[string]string, body []byte) string

	// SourceSignature returns the signature metadata the adapter
	// observed on the inbound request, in a form suitable for
	// inclusion in the canonical attestation body. The returned
	// map MUST be JSON-serializable. By convention it carries the
	// algorithm, a key identifier, and the raw signature value as
	// reported by the upstream. The gateway does not interpret
	// this map; it is recorded verbatim for audit.
	SourceSignature(headers map[string]string) map[string]any
}
