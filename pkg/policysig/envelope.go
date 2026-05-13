package policysig

import (
	"errors"
	"fmt"
	"strings"

	"github.com/intentproof/intentproof-tools/pkg/crypto"
)

// SupportedSignatureAlgorithm enumerates the algorithm strings accepted by
// the policy signature verifier (see pkg/crypto/verifier.go). Keeping this
// list here makes envelope validation a pure-data check that does not need
// to instantiate a verifier.
type SupportedSignatureAlgorithm string

const (
	AlgEd25519   SupportedSignatureAlgorithm = "ed25519"
	AlgECDSAP256 SupportedSignatureAlgorithm = "ecdsa-p256"
	AlgECDSAP384 SupportedSignatureAlgorithm = "ecdsa-p384"
)

// supportedAlgorithms is the canonical lookup table.
var supportedAlgorithms = map[SupportedSignatureAlgorithm]struct{}{
	AlgEd25519:   {},
	AlgECDSAP256: {},
	AlgECDSAP384: {},
}

// Envelope validation errors. Callers can use errors.Is to discriminate.
var (
	ErrNilEnvelope       = errors.New("nil signature envelope")
	ErrMissingAlgorithm  = errors.New("signature envelope: alg is required")
	ErrMissingKeyID      = errors.New("signature envelope: key_id is required")
	ErrMissingValue      = errors.New("signature envelope: value is required")
	ErrUnsupportedAlg    = errors.New("signature envelope: unsupported alg")
)

// IsSupportedAlgorithm reports whether alg is a known signing algorithm
// string. It is intentionally a string-keyed check so callers do not have
// to construct a SupportedSignatureAlgorithm value first.
func IsSupportedAlgorithm(alg string) bool {
	_, ok := supportedAlgorithms[SupportedSignatureAlgorithm(strings.TrimSpace(alg))]
	return ok
}

// ValidateSignatureEnvelope performs shape and algorithm-enum checks on a
// signature envelope. It does NOT verify the signature itself; use
// VerifyPolicySignature for that. The required fields are alg, key_id,
// and value, all non-empty after trimming.
//
// Returns one of ErrNilEnvelope, ErrMissingAlgorithm, ErrMissingKeyID,
// ErrMissingValue, or ErrUnsupportedAlg (each wrapped with the offending
// detail for diagnostics).
func ValidateSignatureEnvelope(env *crypto.SignatureEnvelope) error {
	if env == nil {
		return ErrNilEnvelope
	}
	alg := strings.TrimSpace(env.Alg)
	if alg == "" {
		return ErrMissingAlgorithm
	}
	if strings.TrimSpace(env.KeyID) == "" {
		return ErrMissingKeyID
	}
	if strings.TrimSpace(env.Value) == "" {
		return ErrMissingValue
	}
	if !IsSupportedAlgorithm(alg) {
		return fmt.Errorf("%w: %q", ErrUnsupportedAlg, env.Alg)
	}
	return nil
}
