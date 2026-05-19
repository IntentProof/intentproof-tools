package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type fakeECPolicyKMS struct {
	priv *ecdsa.PrivateKey
}

func (f *fakeECPolicyKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	r, s, err := ecdsa.Sign(rand.Reader, f.priv, in.Message)
	if err != nil {
		return nil, err
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{Signature: der}, nil
}

func TestKMSPolicySignerFromClientRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewKMSPolicySignerFromClient(&fakeECPolicyKMS{priv: priv}, "alias/test")
	if err != nil {
		t.Fatal(err)
	}
	if signer.Algorithm() != "ecdsa-p256" || signer.KeyID() != "alias/test" {
		t.Fatalf("unexpected signer metadata: %s %s", signer.Algorithm(), signer.KeyID())
	}
	digest := KMSDigestSHA256([]byte("policy-body"))
	env, err := signer.Sign(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewPolicySignatureVerifier().Verify([]byte("policy-body"), env, pubDER); err != nil {
		t.Fatal(err)
	}
}

func TestKMSPolicySignerRejectsBadDigestLength(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, err := NewKMSPolicySignerFromClient(&fakeECPolicyKMS{priv: priv}, "k")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(context.Background(), []byte("short")); err == nil {
		t.Fatal("expected digest length error")
	}
}

func TestNewKMSPolicySignerFromClientRequiresClient(t *testing.T) {
	if _, err := NewKMSPolicySignerFromClient(nil, "k"); err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestNewKMSPolicySignerRequiresKeyID(t *testing.T) {
	if _, err := NewKMSPolicySigner(""); err == nil {
		t.Fatal("expected error for empty key id")
	}
}
