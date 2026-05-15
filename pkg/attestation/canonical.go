package attestation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/canon"
)

// CanonicalSchema is the schema identifier embedded in every
// canonical attestation body. It is part of the wire format and
// MUST NOT be changed without a coordinated schema migration.
const CanonicalSchema = "intentproof.attestation.v1"

// DeriveAttestationID returns the deterministic attestation
// identifier for an inbound event. It is computed as
// "att_" + hex(sha256(v1 || json([tenantID, sourceID, sourceEventID])))[:24].
//
// The seed is a version byte (0x01) followed by a JSON array of the
// three strings encoded with encoding/json.Marshal (including Go's
// HTML-safe string escapes for <, >, &, U+2028, and U+2029). This is
// not RFC 8785 JCS; the seed format is frozen for replay idempotency.
// JSON array encoding is unambiguous regardless of string contents.
//
// Determinism is load-bearing: replays of the same upstream event
// MUST resolve to the same attestation id so the gateway can
// idempotently insert.
func DeriveAttestationID(tenantID, sourceID, sourceEventID string) string {
	arr, _ := json.Marshal([3]string{tenantID, sourceID, sourceEventID})
	seed := append([]byte{0x01}, arr...)
	digest := sha256.Sum256(seed)
	return "att_" + hex.EncodeToString(digest[:12])
}

// Subject builds the canonical subject sub-object used in the
// attestation body. When correlationID is non-nil it is recorded
// under "mapping_to.correlation_id" so downstream consumers can
// join attestations to flow runs.
func Subject(subjectType, subjectID string, correlationID *string) map[string]any {
	subject := map[string]any{
		"type": subjectType,
		"id":   subjectID,
	}
	if correlationID != nil {
		subject["mapping_to"] = map[string]any{"correlation_id": *correlationID}
	}
	return subject
}

// CanonicalBody returns the deterministic JSON bytes that the
// platform signs to produce an attestation's platform signature.
//
// Inputs:
//
//   - tenantID, sourceID, attestationID: identifiers for this
//     attestation. attestationID is typically derived via
//     [DeriveAttestationID].
//   - receivedAt: when the gateway received the inbound event.
//   - result: the adapter's normalized [Result].
//   - correlationID: optional correlation lookup result.
//   - sourceSignature: the adapter's observed upstream signature
//     metadata.
//   - payloadHash: sha256 of the original request body, included
//     in the canonical body as "sha256:<hex>".
//
// Timestamps are emitted in RFC3339Nano UTC. The claim_value field
// round-trips the adapter's JSON; if it does not parse, an empty
// object is substituted so the canonical body remains valid JSON.
//
// The returned bytes are stable across runs given identical inputs.
// Callers compute the platform signature as
// ed25519.Sign(key, sha256(bytes)).
func CanonicalBody(
	tenantID string,
	sourceID string,
	attestationID string,
	receivedAt time.Time,
	result Result,
	correlationID *string,
	sourceSignature map[string]any,
	payloadHash []byte,
) ([]byte, error) {
	if len(payloadHash) != 0 && len(payloadHash) != sha256.Size {
		return nil, fmt.Errorf(
			"payloadHash must be %d bytes (sha-256), got %d",
			sha256.Size, len(payloadHash),
		)
	}
	body := map[string]any{
		"schema":                CanonicalSchema,
		"attestation_id":        attestationID,
		"tenant_id":             tenantID,
		"source_id":             sourceID,
		"received_at":           receivedAt.UTC().Format(time.RFC3339Nano),
		"source_emitted_at":     result.SourceEmittedAt.UTC().Format(time.RFC3339Nano),
		"subject":               Subject(result.SubjectType, result.SubjectID, correlationID),
		"claim":                 result.Claim,
		"claim_value":           decodeClaimValue(result.ClaimValue),
		"source_payload_sha256": "sha256:" + hex.EncodeToString(payloadHash),
		"source_signature":      sourceSignature,
	}
	return canon.Marshal(body)
}

// decodeClaimValue rehydrates an adapter's ClaimValue raw JSON into
// a generic Go value so the surrounding struct re-marshals it as
// nested JSON rather than a base64 string. Malformed JSON yields an
// empty object so the canonical body remains a valid JSON document;
// callers that require strict claim shapes MUST validate the value
// before passing it to CanonicalBody.
func decodeClaimValue(raw json.RawMessage) any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return map[string]any{}
	}
	return v
}
