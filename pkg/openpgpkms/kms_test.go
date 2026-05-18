package openpgpkms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func TestKMSSignerUsesSHA512DigestSigning(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	client := &fakeKMSClient{priv: priv, publicDER: publicDER}
	signer, err := NewKMSSignerFromClient(context.Background(), client, "alias/intentproof/pkg-repo")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	digest := sha512.Sum512([]byte("repo metadata"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA512)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if client.signAlgorithm != types.SigningAlgorithmSpecRsassaPkcs1V15Sha512 {
		t.Fatalf("unexpected signing algorithm %s", client.signAlgorithm)
	}
	if client.messageType != types.MessageTypeDigest {
		t.Fatalf("unexpected message type %s", client.messageType)
	}
	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA512, digest[:], sig); err != nil {
		t.Fatalf("verify signature: %v", err)
	}
}

func TestKMSSignerRejectsNonSHA512Digest(t *testing.T) {
	signer := &KMSSigner{keyID: "k", client: &fakeKMSClient{}, public: &rsa.PublicKey{}}
	if _, err := signer.Sign(rand.Reader, []byte("short"), crypto.SHA256); err == nil {
		t.Fatal("expected SHA-256 signing request to fail")
	}
}

type fakeKMSClient struct {
	priv          *rsa.PrivateKey
	publicDER     []byte
	signAlgorithm types.SigningAlgorithmSpec
	messageType   types.MessageType
}

func (c *fakeKMSClient) GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return &kms.GetPublicKeyOutput{
		KeySpec:           types.KeySpecRsa4096,
		KeyUsage:          types.KeyUsageTypeSignVerify,
		PublicKey:         c.publicDER,
		SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecRsassaPkcs1V15Sha512},
	}, nil
}

func (c *fakeKMSClient) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	if c.priv == nil {
		return nil, errors.New("missing private key")
	}
	c.signAlgorithm = in.SigningAlgorithm
	c.messageType = in.MessageType
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.priv, crypto.SHA512, in.Message)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{Signature: sig}, nil
}
