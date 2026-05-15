package crypto

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"
)

// SignatureEnvelope is the canonical JSON representation of a policy signature.
type SignatureEnvelope struct {
	Alg   string `json:"alg"`
	KeyID string `json:"key_id"`
	Value string `json:"value"`
}

// PolicySigner produces SignatureEnvelopes over a SHA-256 digest.
type PolicySigner interface {
	Sign(ctx context.Context, digest []byte) (*SignatureEnvelope, error)
	Algorithm() string
	KeyID() string
}

// NewPolicySignerFromEnv creates a signer based on environment configuration.
// Priority:
//   1. INTENTPROOF_KMS_KEY_ID  -> AWS KMS signer (platform-managed)
//   2. INTENTPROOF_POLICY_SIGNING_KEY_B64 -> local Ed25519 signer (dev/local)
//   3. nil if neither is set
func NewPolicySignerFromEnv() (PolicySigner, error) {
	if kmsKeyID := strings.TrimSpace(os.Getenv("INTENTPROOF_KMS_KEY_ID")); kmsKeyID != "" {
		return NewKMSPolicySigner(kmsKeyID)
	}
	if keyB64 := strings.TrimSpace(os.Getenv("INTENTPROOF_POLICY_SIGNING_KEY_B64")); keyB64 != "" {
		return NewLocalEd25519PolicySignerFromBase64(keyB64)
	}
	return nil, nil
}

// ParseRFC3339OrNow parses an RFC3339 string or returns the current time.
func ParseRFC3339OrNow(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Now().UTC(), nil
	}
	return time.Parse(time.RFC3339, v)
}

// ErrNoSigner indicates no signing configuration is present.
var ErrNoSigner = errors.New("no policy signer configured")
