package policysig

import (
	"errors"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/crypto"
)

func TestValidateSignatureEnvelope_Valid(t *testing.T) {
	cases := []*crypto.SignatureEnvelope{
		{Alg: "ed25519", KeyID: "tenant:k1", Value: "Zm9v"},
		{Alg: "ecdsa-p256", KeyID: "kms:abc", Value: "Zm9v"},
		{Alg: "ecdsa-p384", KeyID: "kms:abc", Value: "Zm9v"},
	}
	for _, env := range cases {
		if err := ValidateSignatureEnvelope(env); err != nil {
			t.Fatalf("unexpected error for %+v: %v", env, err)
		}
	}
}

func TestValidateSignatureEnvelope_Malformed(t *testing.T) {
	cases := []struct {
		name    string
		env     *crypto.SignatureEnvelope
		wantErr error
	}{
		{name: "nil envelope", env: nil, wantErr: ErrNilEnvelope},
		{
			name:    "missing alg",
			env:     &crypto.SignatureEnvelope{Alg: "", KeyID: "k1", Value: "Zm9v"},
			wantErr: ErrMissingAlgorithm,
		},
		{
			name:    "whitespace alg",
			env:     &crypto.SignatureEnvelope{Alg: "   ", KeyID: "k1", Value: "Zm9v"},
			wantErr: ErrMissingAlgorithm,
		},
		{
			name:    "missing key_id",
			env:     &crypto.SignatureEnvelope{Alg: "ed25519", KeyID: "", Value: "Zm9v"},
			wantErr: ErrMissingKeyID,
		},
		{
			name:    "missing value",
			env:     &crypto.SignatureEnvelope{Alg: "ed25519", KeyID: "k1", Value: ""},
			wantErr: ErrMissingValue,
		},
		{
			name:    "unsupported alg",
			env:     &crypto.SignatureEnvelope{Alg: "rsa-4096", KeyID: "k1", Value: "Zm9v"},
			wantErr: ErrUnsupportedAlg,
		},
		{
			name:    "case-sensitive alg rejected",
			env:     &crypto.SignatureEnvelope{Alg: "ED25519", KeyID: "k1", Value: "Zm9v"},
			wantErr: ErrUnsupportedAlg,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSignatureEnvelope(tc.env)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected errors.Is(%v), got %v", tc.wantErr, err)
			}
		})
	}
}

func TestIsSupportedAlgorithm(t *testing.T) {
	for _, alg := range []string{"ed25519", "ecdsa-p256", "ecdsa-p384"} {
		if !IsSupportedAlgorithm(alg) {
			t.Fatalf("expected %q supported", alg)
		}
	}
	for _, alg := range []string{"", "rsa-4096", "ED25519", "secp256k1"} {
		if IsSupportedAlgorithm(alg) {
			t.Fatalf("expected %q unsupported", alg)
		}
	}
}
