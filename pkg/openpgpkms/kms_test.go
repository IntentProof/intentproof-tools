package openpgpkms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/ProtonMail/go-crypto/openpgp"
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

func kmsTestEntity(t *testing.T) (*rsa.PrivateKey, *KMSSigner, *openpgp.Entity) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	kmsSigner, err := NewKMSSignerFromClient(context.Background(), &fakeKMSClient{
		priv:      priv,
		publicDER: publicDER,
	}, "alias/intentproof/pkg-repo")
	if err != nil {
		t.Fatalf("new kms signer: %v", err)
	}
	entity, err := NewEntity(kmsSigner, EntityOptions{
		Name:      DefaultName,
		Email:     DefaultEmail,
		CreatedAt: fixedTime(),
	})
	if err != nil {
		t.Fatalf("new entity from kms signer: %v", err)
	}
	return priv, kmsSigner, entity
}

func TestNewEntityWithKMSSigner(t *testing.T) {
	_, _, entity := kmsTestEntity(t)
	identity := entity.PrimaryIdentity()
	if identity == nil || identity.SelfSignature == nil {
		t.Fatal("expected primary identity self-signature")
	}
	if len(identity.SelfSignature.IssuerFingerprint) == 0 {
		t.Fatal("expected issuer fingerprint subpacket on kms-backed self-signature")
	}
}

func TestKMSSignerArmoredClearSignVerifiesWithGPGWhenAvailable(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	_, _, entity := kmsTestEntity(t)

	dir, err := os.MkdirTemp("/tmp", "ipkmsclr-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	message := []byte("Origin: IntentProof\nSuite: stable\n")
	messagePath := filepath.Join(dir, "Release")
	inreleasePath := filepath.Join(dir, "InRelease")
	releaseSigPath := filepath.Join(dir, "Release.gpg")
	keyPath := filepath.Join(dir, "intentproof.gpg")
	if err := os.WriteFile(messagePath, message, 0o644); err != nil {
		t.Fatalf("write message: %v", err)
	}
	var publicKey bytes.Buffer
	if err := ArmoredPublicKey(&publicKey, entity); err != nil {
		t.Fatalf("export public key: %v", err)
	}
	if err := os.WriteFile(keyPath, publicKey.Bytes(), 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	var releaseSig bytes.Buffer
	if err := ArmoredDetachSign(&releaseSig, entity, bytes.NewReader(message), fixedTime()); err != nil {
		t.Fatalf("detach sign: %v", err)
	}
	if err := os.WriteFile(releaseSigPath, releaseSig.Bytes(), 0o644); err != nil {
		t.Fatalf("write release signature: %v", err)
	}
	var clearsigned bytes.Buffer
	if err := ArmoredClearSign(&clearsigned, entity, bytes.NewReader(message), fixedTime()); err != nil {
		t.Fatalf("clear sign: %v", err)
	}
	if err := os.WriteFile(inreleasePath, clearsigned.Bytes(), 0o644); err != nil {
		t.Fatalf("write InRelease: %v", err)
	}

	home := filepath.Join(dir, "gnupg")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatalf("mkdir gnupg home: %v", err)
	}
	runGPG(t, home, "--import", keyPath)
	runGPG(t, home, "--verify", releaseSigPath, messagePath)
	runGPG(t, home, "--verify", inreleasePath)
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
