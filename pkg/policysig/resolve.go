package policysig

import (
	"errors"
	"fmt"
	"time"
)

// KeyRecord is the minimal projection of a tenant signing key needed to
// evaluate activation-window resolution. It deliberately mirrors the
// fields used by intentproof-core's TenantSigningKeyRecord that
// participate in the resolve decision; it does NOT include public-key
// bytes or other transport-only fields, so callers may construct it from
// any storage backend.
//
// Window semantics (the contract H8 locks in):
//
//   - ActivatedAt is the inclusive lower bound. A key is usable from
//     ActivatedAt onward (signedAt >= ActivatedAt).
//   - DeactivatedAt, when non-nil, is the EXCLUSIVE upper bound. A key
//     is usable strictly before DeactivatedAt (signedAt < DeactivatedAt).
//     This matches the core PostgresStore predicate
//     `activated_at <= $signed_at AND (deactivated_at IS NULL OR
//     $signed_at < deactivated_at)` and the MemoryStore guard
//     `!signedAt.Before(*DeactivatedAt)` returning ErrKeyNotActive.
//   - Status MUST be KeyStatusActive at resolution time. KeyStatusRevoked
//     and KeyStatusInactive are explicitly rejected even if the timestamp
//     falls inside the activation window. This is the H8 "status honored
//     at resolution time" CHECK.
type KeyRecord struct {
	TenantID      string
	KeyID         string
	Algorithm     string
	Status        KeyStatus
	ActivatedAt   time.Time
	DeactivatedAt *time.Time
}

// ErrKeyNotActive is returned by ResolveKeyAt when the candidate key is
// outside its activation window for the supplied timestamp.
var ErrKeyNotActive = errors.New("signing key not active for signed_at")

// ErrKeyNotUsable is returned by ResolveKeyAt when the candidate key is
// within its activation window but its Status is not KeyStatusActive
// (i.e. KeyStatusInactive or KeyStatusRevoked). This is the H8 status
// CHECK; it is distinct from ErrKeyNotActive so callers can log the
// status explicitly.
var ErrKeyNotUsable = errors.New("signing key not usable due to status")

// ResolveKeyAt evaluates a candidate KeyRecord against signedAt and the
// status invariant. It returns nil iff:
//
//  1. record is non-nil,
//  2. record.Status == KeyStatusActive,
//  3. signedAt >= record.ActivatedAt, AND
//  4. record.DeactivatedAt is nil OR signedAt < *record.DeactivatedAt.
//
// On failure it returns:
//   - ErrKeyNotActive (wrapped) if the timestamp is outside the window.
//   - ErrKeyNotUsable (wrapped) if the status is not KeyStatusActive.
//
// Callers that wish to surface different error codes (e.g. 404 vs 410)
// can use errors.Is to discriminate.
func ResolveKeyAt(record *KeyRecord, signedAt time.Time) error {
	if record == nil {
		return fmt.Errorf("%w: nil record", ErrKeyNotActive)
	}
	// Status check first: a revoked or inactive key must never resolve,
	// regardless of timestamp. This is the H8 invariant.
	if !record.Status.IsUsable() {
		return fmt.Errorf("%w: status=%q", ErrKeyNotUsable, record.Status)
	}
	if record.ActivatedAt.After(signedAt) {
		return fmt.Errorf(
			"%w: signed_at=%s before activated_at=%s",
			ErrKeyNotActive, signedAt.Format(time.RFC3339Nano),
			record.ActivatedAt.Format(time.RFC3339Nano),
		)
	}
	if record.DeactivatedAt != nil && !signedAt.Before(*record.DeactivatedAt) {
		return fmt.Errorf(
			"%w: signed_at=%s not before deactivated_at=%s",
			ErrKeyNotActive, signedAt.Format(time.RFC3339Nano),
			record.DeactivatedAt.Format(time.RFC3339Nano),
		)
	}
	return nil
}
