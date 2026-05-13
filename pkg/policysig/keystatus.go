package policysig

import (
	"errors"
	"fmt"
	"strings"
)

// KeyStatus is the canonical lifecycle status for a tenant signing key.
//
// The canonical set is mirrored from intentproof-core (query-api/types.go).
// Tools is Tier 1, so the set is duplicated here rather than imported.
// If the canonical set ever needs to grow, update both sides in lockstep
// (the Tier 1 surface is the authoritative contract per ADR-010).
type KeyStatus string

const (
	// KeyStatusActive indicates the key may be used to verify signatures
	// during its activation window.
	KeyStatusActive KeyStatus = "active"

	// KeyStatusInactive indicates the key has been provisioned but is not
	// (yet) usable. A key with this status MUST NOT resolve to a usable
	// signer regardless of timestamp.
	KeyStatusInactive KeyStatus = "inactive"

	// KeyStatusRevoked indicates the key has been retired and MUST NOT
	// resolve to a usable signer regardless of timestamp. Stored records
	// remain queryable for forensic / historical purposes; ResolveKeyAt
	// will refuse them.
	KeyStatusRevoked KeyStatus = "revoked"
)

// ErrUnknownKeyStatus is returned by NormalizeKeyStatus when the input
// does not match the canonical set.
var ErrUnknownKeyStatus = errors.New("unknown signing key status")

// allowedKeyStatuses is the canonical lookup table for normalization.
var allowedKeyStatuses = map[KeyStatus]struct{}{
	KeyStatusActive:   {},
	KeyStatusInactive: {},
	KeyStatusRevoked:  {},
}

// NormalizeKeyStatus trims/lowercases the input and returns the canonical
// KeyStatus value. An empty string defaults to KeyStatusActive (matching
// the core behavior for SaveTenantSigningKey records with omitted status).
// An unrecognized value returns ErrUnknownKeyStatus wrapped with the raw
// input for debuggability.
func NormalizeKeyStatus(raw string) (KeyStatus, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return KeyStatusActive, nil
	}
	candidate := KeyStatus(trimmed)
	if _, ok := allowedKeyStatuses[candidate]; !ok {
		return "", fmt.Errorf("%w: %q (must be one of: active, inactive, revoked)", ErrUnknownKeyStatus, raw)
	}
	return candidate, nil
}

// IsUsable reports whether the given status is permitted to resolve to a
// usable signer. Only KeyStatusActive is usable; KeyStatusInactive and
// KeyStatusRevoked are not.
func (s KeyStatus) IsUsable() bool {
	return s == KeyStatusActive
}
