package openpgpkms

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func TestVerifyAptMetadataFilesHappyPath(t *testing.T) {
	entity := testEntity(t)
	dir, err := os.MkdirTemp("/tmp", "ipapt-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	message := []byte("Origin: IntentProof\nSuite: stable\n")
	messagePath := filepath.Join(dir, "Release")
	if err := os.WriteFile(messagePath, message, 0o644); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "intentproof.gpg")
	var publicKey bytes.Buffer
	if err := ArmoredPublicKey(&publicKey, entity); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, publicKey.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	var releaseSig bytes.Buffer
	if err := ArmoredDetachSign(&releaseSig, entity, bytes.NewReader(message), fixedTime()); err != nil {
		t.Fatal(err)
	}
	sigPath := filepath.Join(dir, "Release.gpg")
	if err := os.WriteFile(sigPath, releaseSig.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	var inrelease bytes.Buffer
	if err := ArmoredClearSign(&inrelease, entity, bytes.NewReader(message), fixedTime()); err != nil {
		t.Fatal(err)
	}
	inreleasePath := filepath.Join(dir, "InRelease")
	if err := os.WriteFile(inreleasePath, inrelease.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAptMetadataFiles(keyPath, messagePath, sigPath, inreleasePath); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAptMetadataFilesRejectsMismatchedRelease(t *testing.T) {
	artifacts := writePackageSigningArtifacts(t, "ipaptbad-*")
	var inrelease bytes.Buffer
	entity := testEntity(t)
	if err := ArmoredClearSign(&inrelease, entity, bytes.NewReader([]byte("different release body\n")), fixedTime()); err != nil {
		t.Fatal(err)
	}
	inreleasePath := filepath.Join(artifacts.dir, "InRelease")
	if err := os.WriteFile(inreleasePath, inrelease.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	err := VerifyAptMetadataFiles(artifacts.keyPath, artifacts.messagePath, artifacts.sigPath, inreleasePath)
	if err == nil || !strings.Contains(err.Error(), "does not match Release") {
		t.Fatalf("expected mismatch error, got %v", err)
	}
}

func TestVerifyAptMetadataRejectsMissingInputs(t *testing.T) {
	if err := VerifyAptMetadata(nil, nil, nil, nil); err == nil {
		t.Fatal("expected error for nil readers")
	}
}

func TestNewKMSSignerFromClientRejectsUnsupportedKeySpec(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	client := &staticKMSClient{getOut: &kms.GetPublicKeyOutput{
		KeySpec:           types.KeySpecEccNistP256,
		KeyUsage:          types.KeyUsageTypeSignVerify,
		PublicKey:         publicDER,
		SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecRsassaPkcs1V15Sha512},
	}}
	if _, err := NewKMSSignerFromClient(context.Background(), client, "alias/test"); err == nil {
		t.Fatal("expected unsupported key spec error")
	}
}

type staticKMSClient struct {
	getOut *kms.GetPublicKeyOutput
}

func (c *staticKMSClient) GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return c.getOut, nil
}

func (c *staticKMSClient) Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error) {
	return nil, nil
}
