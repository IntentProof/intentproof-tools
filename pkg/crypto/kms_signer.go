package crypto

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSPolicySigner uses AWS KMS asymmetric signing for platform-managed keys.
type KMSPolicySigner struct {
	client kmsPolicySignClient
	keyID  string
}

type kmsPolicySignClient interface {
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

// NewKMSPolicySigner creates a KMS signer for the given key ID (ARN or alias).
func NewKMSPolicySigner(keyID string) (PolicySigner, error) {
	if keyID == "" {
		return nil, fmt.Errorf("KMS key ID is required")
	}
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return NewKMSPolicySignerFromClient(kms.NewFromConfig(cfg), keyID)
}

// NewKMSPolicySignerFromClient creates a KMS signer from an injected API client.
func NewKMSPolicySignerFromClient(client kmsPolicySignClient, keyID string) (PolicySigner, error) {
	if client == nil {
		return nil, fmt.Errorf("KMS client is required")
	}
	if keyID == "" {
		return nil, fmt.Errorf("KMS key ID is required")
	}
	return &KMSPolicySigner{
		client: client,
		keyID:  keyID,
	}, nil
}

func (s *KMSPolicySigner) Algorithm() string { return "ecdsa-p256" }
func (s *KMSPolicySigner) KeyID() string      { return s.keyID }

func (s *KMSPolicySigner) Sign(ctx context.Context, digest []byte) (*SignatureEnvelope, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("invalid digest length %d: expected 32 for sha256", len(digest))
	}
	out, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            &s.keyID,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("kms sign: %w", err)
	}
	return &SignatureEnvelope{
		Alg:   s.Algorithm(),
		KeyID: s.KeyID(),
		Value: base64.StdEncoding.EncodeToString(out.Signature),
	}, nil
}

// KMSDigestSHA256 computes a SHA-256 digest suitable for KMS signing.
func KMSDigestSHA256(data []byte) []byte {
	d := sha256.Sum256(data)
	return d[:]
}
