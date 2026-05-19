package openpgpkms

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
)

// VerifyAptMetadata checks Release.gpg and an armored clearsigned InRelease
// against an exported OpenPGP public key.
func VerifyAptMetadata(publicKey io.Reader, release, releaseSig, inrelease io.Reader) error {
	if publicKey == nil {
		return fmt.Errorf("public key is required")
	}
	if release == nil || releaseSig == nil || inrelease == nil {
		return fmt.Errorf("release, Release.gpg, and InRelease are required")
	}
	keyring, err := openpgp.ReadArmoredKeyRing(publicKey)
	if err != nil {
		return fmt.Errorf("read armored public key: %w", err)
	}
	releaseBytes, err := io.ReadAll(release)
	if err != nil {
		return fmt.Errorf("read release: %w", err)
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(releaseBytes), releaseSig, nil); err != nil {
		return fmt.Errorf("verify Release.gpg: %w", err)
	}
	inreleaseBytes, err := io.ReadAll(inrelease)
	if err != nil {
		return fmt.Errorf("read InRelease: %w", err)
	}
	block, _ := clearsign.Decode(inreleaseBytes)
	if block == nil {
		return fmt.Errorf("decode clearsigned InRelease")
	}
	if !bytes.Equal(block.Plaintext, releaseBytes) {
		return fmt.Errorf("InRelease plaintext does not match Release")
	}
	if _, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(block.Bytes), block.ArmoredSignature.Body, nil); err != nil {
		return fmt.Errorf("verify InRelease signature: %w", err)
	}
	return nil
}

// VerifyAptMetadataFiles is a convenience wrapper around VerifyAptMetadata.
func VerifyAptMetadataFiles(publicKeyPath, releasePath, releaseSigPath, inreleasePath string) error {
	publicKey, err := os.Open(publicKeyPath)
	if err != nil {
		return fmt.Errorf("open public key: %w", err)
	}
	defer publicKey.Close()
	release, err := os.Open(releasePath)
	if err != nil {
		return fmt.Errorf("open release: %w", err)
	}
	defer release.Close()
	releaseSig, err := os.Open(releaseSigPath)
	if err != nil {
		return fmt.Errorf("open Release.gpg: %w", err)
	}
	defer releaseSig.Close()
	inrelease, err := os.Open(inreleasePath)
	if err != nil {
		return fmt.Errorf("open InRelease: %w", err)
	}
	defer inrelease.Close()
	return VerifyAptMetadata(publicKey, release, releaseSig, inrelease)
}
