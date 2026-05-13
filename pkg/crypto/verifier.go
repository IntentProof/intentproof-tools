package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/ssh"
)

// PolicySignatureVerifier verifies policy signatures against stored public keys.
type PolicySignatureVerifier struct{}

// NewPolicySignatureVerifier creates a verifier.
func NewPolicySignatureVerifier() *PolicySignatureVerifier {
	return &PolicySignatureVerifier{}
}

// Verify checks the signature envelope against the canonical payload and public key.
// The public key may be provided as raw bytes (DER or OpenSSH format) or base64-encoded.
func (v *PolicySignatureVerifier) Verify(canonicalPayload []byte, env *SignatureEnvelope, pubKey []byte) error {
	if env == nil {
		return errors.New("nil SignatureEnvelope")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(env.Value)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	digest := sha256.Sum256(canonicalPayload)

	switch env.Alg {
	case "ed25519":
		return verifyEd25519(digest[:], sigBytes, pubKey)
	case "ecdsa-p256":
		return verifyECDSA(elliptic.P256(), digest[:], sigBytes, pubKey)
	case "ecdsa-p384":
		return verifyECDSA(elliptic.P384(), digest[:], sigBytes, pubKey)
	default:
		return fmt.Errorf("unsupported signing algorithm: %s", env.Alg)
	}
}

func verifyEd25519(digest, sig, pubKey []byte) error {
	// Try parsing as OpenSSH public key first, then raw.
	pub, err := parseEd25519PublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("parse ed25519 public key: %w", err)
	}
	if !ed25519.Verify(pub, digest, sig) {
		return errors.New("ed25519 signature verification failed")
	}
	return nil
}

func parseEd25519PublicKey(pubKey []byte) (ed25519.PublicKey, error) {
	// Raw 32-byte key.
	if len(pubKey) == ed25519.PublicKeySize {
		pk := make([]byte, ed25519.PublicKeySize)
		copy(pk, pubKey)
		return pk, nil
	}

	// Try base64 decoding first.
	decoded, err := base64.StdEncoding.DecodeString(string(pubKey))
	if err == nil {
		if len(decoded) == ed25519.PublicKeySize {
			pk := make([]byte, ed25519.PublicKeySize)
			copy(pk, decoded)
			return pk, nil
		}
		// Not a raw 32-byte key; feed decoded bytes into OpenSSH/PKIX paths.
		pubKey = decoded
	}

	// Try OpenSSH public key format.
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(pubKey)
	if err == nil {
		if pk, ok := parsed.(ssh.CryptoPublicKey); ok {
			if ed, ok := pk.CryptoPublicKey().(ed25519.PublicKey); ok {
				out := make([]byte, len(ed))
				copy(out, ed)
				return out, nil
			}
		}
	}

	// Try PKIX/DER format.
	if pk, err := x509.ParsePKIXPublicKey(pubKey); err == nil {
		if ed, ok := pk.(ed25519.PublicKey); ok {
			out := make([]byte, len(ed))
			copy(out, ed)
			return out, nil
		}
	}

	return nil, errors.New("unable to parse ed25519 public key")
}

func verifyECDSA(curve elliptic.Curve, digest, sig, pubKey []byte) error {
	pub, err := parseECDSAPublicKey(curve, pubKey)
	if err != nil {
		return fmt.Errorf("parse ecdsa public key: %w", err)
	}

	// ECDSA signatures from KMS are ASN.1 DER encoded.
	parsedSig, err := parseECDSASignature(curve, sig)
	if err != nil {
		return fmt.Errorf("parse ecdsa signature: %w", err)
	}

	if !ecdsa.Verify(pub, digest, parsedSig.R, parsedSig.S) {
		return errors.New("ecdsa signature verification failed")
	}
	return nil
}

func parseECDSAPublicKey(curve elliptic.Curve, pubKey []byte) (*ecdsa.PublicKey, error) {
	// Try base64 decode first.
	decoded, err := base64.StdEncoding.DecodeString(string(pubKey))
	if err == nil {
		pubKey = decoded
	}

	// Try PKIX/DER.
	if pk, err := x509.ParsePKIXPublicKey(pubKey); err == nil {
		if ecdsaPub, ok := pk.(*ecdsa.PublicKey); ok {
			if ecdsaPub.Curve == curve {
				return ecdsaPub, nil
			}
		}
	}

	// Try uncompressed point (SEC1).
	coordLen := curve.Params().BitSize / 8
	if len(pubKey) == 1+2*coordLen && pubKey[0] == 0x04 {
		xInt := new(big.Int).SetBytes(pubKey[1 : 1+coordLen])
		yInt := new(big.Int).SetBytes(pubKey[1+coordLen:])
		return &ecdsa.PublicKey{Curve: curve, X: xInt, Y: yInt}, nil
	}

	return nil, errors.New("unable to parse ecdsa public key")
}

type ecdsaSignature struct {
	R, S *big.Int
}

func parseECDSASignature(curve elliptic.Curve, sig []byte) (*ecdsaSignature, error) {
	// Try ASN.1 DER first; reject if trailing bytes remain.
	var der struct {
		R, S *big.Int
	}
	rest, err := asn1.Unmarshal(sig, &der)
	if err == nil && len(rest) == 0 && der.R != nil && der.S != nil {
		return &ecdsaSignature{R: der.R, S: der.S}, nil
	}

	// Fall back to raw (R || S) concatenation with exact length checks.
	var expected int
	switch curve {
	case elliptic.P256():
		expected = 64
	case elliptic.P384():
		expected = 96
	default:
		return nil, errors.New("unsupported ecdsa curve for raw signature")
	}
	if len(sig) == expected {
		pointLen := expected / 2
		r := new(big.Int).SetBytes(sig[:pointLen])
		s := new(big.Int).SetBytes(sig[pointLen:])
		return &ecdsaSignature{R: r, S: s}, nil
	}

	return nil, errors.New("unable to parse ecdsa signature")
}

// ExtractSignatureEnvelope parses a signature envelope from a raw JSON body map.
func ExtractSignatureEnvelope(bodyMap map[string]any) (*SignatureEnvelope, error) {
	rawSig, ok := bodyMap["signature"]
	if !ok || rawSig == nil {
		return nil, errors.New("signature missing")
	}
	sigBytes, err := json.Marshal(rawSig)
	if err != nil {
		return nil, fmt.Errorf("marshal signature: %w", err)
	}
	var env SignatureEnvelope
	if err := json.Unmarshal(sigBytes, &env); err != nil {
		return nil, fmt.Errorf("parse signature envelope: %w", err)
	}
	return &env, nil
}
