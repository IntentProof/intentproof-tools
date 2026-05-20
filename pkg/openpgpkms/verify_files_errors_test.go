package openpgpkms

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyAptMetadataFilesMissingKey(t *testing.T) {
	err := VerifyAptMetadataFiles("/no/such/key.gpg", "r", "s", "i")
	if err == nil || !strings.Contains(err.Error(), "open public key") {
		t.Fatalf("err=%v", err)
	}
}

func TestVerifyAptMetadataFilesMissingRelease(t *testing.T) {
	artifacts := writePackageSigningArtifacts(t, "ipaptmiss-*")
	err := VerifyAptMetadataFiles(artifacts.keyPath, "/no/release", artifacts.sigPath, filepath.Join(artifacts.dir, "InRelease"))
	if err == nil || !strings.Contains(err.Error(), "open release") {
		t.Fatalf("err=%v", err)
	}
}
