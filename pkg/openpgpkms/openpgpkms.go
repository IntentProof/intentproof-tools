package openpgpkms

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

const (
	DefaultName  = "IntentProof Package Repository"
	DefaultEmail = "packages@intentproof.io"
)

// EntityOptions describes the OpenPGP identity wrapped around a KMS key.
type EntityOptions struct {
	Name      string
	Comment   string
	Email     string
	CreatedAt time.Time
}

// NewEntity builds a signing-only OpenPGP entity around an RSA crypto.Signer.
func NewEntity(signer crypto.Signer, opts EntityOptions) (*openpgp.Entity, error) {
	if signer == nil {
		return nil, fmt.Errorf("signer is required")
	}
	if _, ok := signer.Public().(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("OpenPGP package signing requires an RSA public key")
	}
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		name = DefaultName
	}
	email := strings.TrimSpace(opts.Email)
	if email == "" {
		email = DefaultEmail
	}
	createdAt := opts.CreatedAt.UTC()
	if createdAt.IsZero() {
		return nil, fmt.Errorf("OpenPGP creation time is required for stable fingerprints")
	}

	uid := packet.NewUserId(name, strings.TrimSpace(opts.Comment), email)
	if uid == nil {
		return nil, fmt.Errorf("invalid OpenPGP user ID components")
	}
	privateKey := packet.NewSignerPrivateKey(createdAt, signer)
	if privateKey.PubKeyAlgo != packet.PubKeyAlgoRSA {
		return nil, fmt.Errorf("OpenPGP package signing requires RSA, got %v", privateKey.PubKeyAlgo)
	}

	entity := &openpgp.Entity{
		PrimaryKey: &privateKey.PublicKey,
		PrivateKey: privateKey,
		Identities: map[string]*openpgp.Identity{},
	}
	selfSig := &packet.Signature{
		SigType:       packet.SigTypePositiveCert,
		PubKeyAlgo:    privateKey.PubKeyAlgo,
		Hash:          crypto.SHA512,
		CreationTime:  createdAt,
		IssuerKeyId:   &privateKey.KeyId,
		FlagsValid:    true,
		FlagCertify:   true,
		FlagSign:      true,
		IsPrimaryId:   boolPtr(true),
		PreferredHash: []uint8{10}, // SHA-512, RFC 4880 section 9.4.
	}
	if err := selfSig.SignUserId(uid.Id, entity.PrimaryKey, privateKey, pgpConfig(createdAt)); err != nil {
		return nil, fmt.Errorf("self-sign OpenPGP user ID: %w", err)
	}
	entity.Identities[uid.Id] = &openpgp.Identity{
		Name:          uid.Id,
		UserId:        uid,
		SelfSignature: selfSig,
	}
	return entity, nil
}

// ArmoredPublicKey writes an ASCII-armored OpenPGP public key block.
func ArmoredPublicKey(w io.Writer, entity *openpgp.Entity) error {
	if entity == nil {
		return fmt.Errorf("entity is required")
	}
	out, err := armor.Encode(w, openpgp.PublicKeyType, nil)
	if err != nil {
		return fmt.Errorf("encode public key armor: %w", err)
	}
	if err := entity.Serialize(out); err != nil {
		_ = out.Close()
		return fmt.Errorf("serialize public key: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close public key armor: %w", err)
	}
	return nil
}

// ArmoredDetachSign writes an ASCII-armored detached OpenPGP signature.
func ArmoredDetachSign(w io.Writer, entity *openpgp.Entity, message io.Reader, createdAt time.Time) error {
	if entity == nil {
		return fmt.Errorf("entity is required")
	}
	if message == nil {
		return fmt.Errorf("message is required")
	}
	if createdAt.IsZero() {
		return fmt.Errorf("OpenPGP signature creation time is required")
	}
	if err := openpgp.ArmoredDetachSign(w, entity, message, pgpConfig(createdAt)); err != nil {
		return fmt.Errorf("OpenPGP detached sign: %w", err)
	}
	return nil
}

// Fingerprint returns the canonical uppercase hex fingerprint for an entity.
func Fingerprint(entity *openpgp.Entity) string {
	if entity == nil || entity.PrimaryKey == nil {
		return ""
	}
	return fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint[:])
}

func pgpConfig(createdAt time.Time) *packet.Config {
	t := createdAt.UTC()
	return &packet.Config{
		DefaultHash: crypto.SHA512,
		Time: func() time.Time {
			return t
		},
	}
}

func boolPtr(v bool) *bool {
	return &v
}
