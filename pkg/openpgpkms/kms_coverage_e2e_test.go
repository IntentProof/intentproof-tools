package openpgpkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type kmsErrClient struct{ err error }

func (c *kmsErrClient) GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return nil, c.err
}

func (c *kmsErrClient) Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error) {
	return nil, c.err
}

func TestNewKMSSignerFromClientErrors(t *testing.T) {
	if _, err := NewKMSSignerFromClient(context.Background(), nil, "k"); err == nil {
		t.Fatal("nil client")
	}
	if _, err := NewKMSSignerFromClient(context.Background(), &fakeKMSClient{}, ""); err == nil {
		t.Fatal("empty key")
	}
	if _, err := NewKMSSignerFromClient(context.Background(), &kmsErrClient{err: errors.New("boom")}, "k"); err == nil {
		t.Fatal("get public key error")
	}
}

func TestNewKMSSignerFromClientRejectsKeyUsageAndAlgorithms(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	client := &staticKMSClient{getOut: &kms.GetPublicKeyOutput{
		KeySpec:   types.KeySpecRsa4096,
		KeyUsage:  types.KeyUsageTypeEncryptDecrypt,
		PublicKey: der,
	}}
	if _, err := NewKMSSignerFromClient(context.Background(), client, "k"); err == nil {
		t.Fatal("usage")
	}
	client.getOut.KeyUsage = types.KeyUsageTypeSignVerify
	client.getOut.SigningAlgorithms = []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256}
	if _, err := NewKMSSignerFromClient(context.Background(), client, "k"); err == nil {
		t.Fatal("algorithms")
	}
}

func TestNewKMSSignerFromClientRejectsNonRSAPublicKey(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	client := &staticKMSClient{getOut: &kms.GetPublicKeyOutput{
		KeySpec:           types.KeySpecRsa4096,
		KeyUsage:          types.KeyUsageTypeSignVerify,
		PublicKey:         der,
		SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecRsassaPkcs1V15Sha512},
	}}
	if _, err := NewKMSSignerFromClient(context.Background(), client, "k"); err == nil {
		t.Fatal("non-rsa")
	}
}

func TestKMSSignerSignValidation(t *testing.T) {
	var s *KMSSigner
	if _, err := s.Sign(rand.Reader, make([]byte, 64), crypto.SHA512); err == nil {
		t.Fatal("nil signer")
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	signer, err := NewKMSSignerFromClient(context.Background(), &fakeKMSClient{priv: priv, publicDER: der}, "alias/test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(rand.Reader, []byte("short"), crypto.SHA512); err == nil {
		t.Fatal("digest length")
	}
	if _, err := signer.Sign(rand.Reader, make([]byte, 64), crypto.SHA256); err == nil {
		t.Fatal("hash func")
	}
	digest := sha512.Sum512([]byte("x"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA512); err != nil {
		t.Fatal(err)
	}
}

func TestSupportsSigningAlgorithmFalse(t *testing.T) {
	if supportsSigningAlgorithm([]types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
		types.SigningAlgorithmSpecRsassaPkcs1V15Sha512) {
		t.Fatal("expected false")
	}
}
