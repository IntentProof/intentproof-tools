package openpgpkms

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type kmsClient interface {
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

// KMSSigner adapts an AWS KMS RSA_4096 SIGN_VERIFY key to crypto.Signer.
type KMSSigner struct {
	ctx    context.Context
	client kmsClient
	keyID  string
	public *rsa.PublicKey
}

// NewKMSSigner creates a KMS-backed signer using the default AWS config chain.
func NewKMSSigner(ctx context.Context, keyID string) (*KMSSigner, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return nil, fmt.Errorf("KMS key ID is required")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return NewKMSSignerFromClient(ctx, kms.NewFromConfig(cfg), keyID)
}

// NewKMSSignerFromClient creates a KMS-backed signer from an injected client.
func NewKMSSignerFromClient(ctx context.Context, client kmsClient, keyID string) (*KMSSigner, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		return nil, fmt.Errorf("KMS client is required")
	}
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return nil, fmt.Errorf("KMS key ID is required")
	}
	out, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, fmt.Errorf("kms get public key: %w", err)
	}
	if out.KeySpec != "" && out.KeySpec != types.KeySpecRsa4096 {
		return nil, fmt.Errorf("KMS key %s has unsupported key spec %s", keyID, out.KeySpec)
	}
	if out.KeyUsage != "" && out.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("KMS key %s has unsupported key usage %s", keyID, out.KeyUsage)
	}
	if len(out.SigningAlgorithms) > 0 && !supportsSigningAlgorithm(out.SigningAlgorithms, types.SigningAlgorithmSpecRsassaPkcs1V15Sha512) {
		return nil, fmt.Errorf("KMS key %s does not support %s", keyID, types.SigningAlgorithmSpecRsassaPkcs1V15Sha512)
	}
	public, err := parseRSAPublicKey(out.PublicKey)
	if err != nil {
		return nil, err
	}
	return &KMSSigner{
		ctx:    ctx,
		client: client,
		keyID:  keyID,
		public: public,
	}, nil
}

func (s *KMSSigner) Public() crypto.PublicKey {
	return s.public
}

func (s *KMSSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("KMS signer is nil")
	}
	if opts == nil || opts.HashFunc() != crypto.SHA512 {
		return nil, fmt.Errorf("KMS OpenPGP signatures require SHA-512")
	}
	if len(digest) != crypto.SHA512.Size() {
		return nil, fmt.Errorf("invalid SHA-512 digest length %d", len(digest))
	}
	out, err := s.client.Sign(s.ctx, &kms.SignInput{
		KeyId:            &s.keyID,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
	})
	if err != nil {
		return nil, fmt.Errorf("kms sign: %w", err)
	}
	return out.Signature, nil
}

func parseRSAPublicKey(der []byte) (*rsa.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse KMS public key: %w", err)
	}
	public, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("KMS public key is %T, expected *rsa.PublicKey", parsed)
	}
	return public, nil
}

func supportsSigningAlgorithm(have []types.SigningAlgorithmSpec, want types.SigningAlgorithmSpec) bool {
	for _, alg := range have {
		if alg == want {
			return true
		}
	}
	return false
}
