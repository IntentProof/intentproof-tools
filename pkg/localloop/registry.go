package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// LocalTenantID is the default tenant for intentproof local.
const LocalTenantID = "tnt_local"

// ErrUnknownSDK means the (tenant_id, instance_id) pair is not registered.
var ErrUnknownSDK = errors.New("localloop: unknown or revoked sdk instance")

// ErrSignatureVerification means Ed25519 verification failed.
var ErrSignatureVerification = errors.New("localloop: signature verification failed")

// ErrInvalidRequest signals malformed event fields.
var ErrInvalidRequest = errors.New("localloop: invalid request")

type sdkKeypairFile struct {
	PrivateKey string `json:"privateKey"`
	InstanceID string `json:"instanceId"`
}

// EnsureTenant inserts the tenant row when missing.
func EnsureTenant(ctx context.Context, db *sql.DB, tenantID string) error {
	_, err := db.ExecContext(ctx, `
INSERT INTO tenants (tenant_id, display_name, created_at, status)
VALUES (?, ?, ?, 'active')
ON CONFLICT (tenant_id) DO NOTHING`,
		tenantID, tenantID, time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("ensure tenant: %w", err)
	}
	return nil
}

// RegisterSDKInstance records an SDK public key for ingest verification.
func RegisterSDKInstance(
	ctx context.Context,
	db *sql.DB,
	tenantID, instanceID string,
	pub ed25519.PublicKey,
) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("register sdk: invalid public key length %d", len(pub))
	}
	if err := EnsureTenant(ctx, db, tenantID); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, `
INSERT INTO sdk_instances (tenant_id, instance_id, public_key, registered_at, revoked_at)
VALUES (?, ?, ?, ?, NULL)
ON CONFLICT (tenant_id, instance_id) DO UPDATE SET
  public_key = excluded.public_key,
  revoked_at = NULL`,
		tenantID, instanceID, []byte(pub), time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("register sdk instance: %w", err)
	}
	return nil
}

func lookupPublicKey(
	ctx context.Context,
	db *sql.DB,
	tenantID, instanceID string,
) (ed25519.PublicKey, error) {
	var pub []byte
	err := db.QueryRowContext(ctx, `
SELECT public_key FROM sdk_instances
WHERE tenant_id = ? AND instance_id = ? AND revoked_at IS NULL`,
		tenantID, instanceID,
	).Scan(&pub)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUnknownSDK
		}
		return nil, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid public key length", ErrUnknownSDK)
	}
	return ed25519.PublicKey(pub), nil
}

// LoadSDKPublicKeysForCorrelation returns bundle key entries for the SDK
// instances that emitted events in a correlation.
func LoadSDKPublicKeysForCorrelation(
	ctx context.Context,
	db *sql.DB,
	tenantID, correlationID string,
) (map[string][]byte, error) {
	rows, err := db.QueryContext(ctx, `
SELECT DISTINCT e.instance_id, s.public_key
FROM execution_events e
JOIN sdk_instances s
  ON s.tenant_id = e.tenant_id
 AND s.instance_id = e.instance_id
WHERE e.tenant_id = ? AND e.correlation_id = ?
ORDER BY e.instance_id ASC`,
		tenantID, correlationID,
	)
	if err != nil {
		return nil, fmt.Errorf("load sdk public keys: %w", err)
	}
	defer rows.Close()

	keys := map[string][]byte{}
	for rows.Next() {
		var instanceID string
		var pub []byte
		if err := rows.Scan(&instanceID, &pub); err != nil {
			return nil, fmt.Errorf("scan sdk public key: %w", err)
		}
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("load sdk public keys: invalid public key length for %s", instanceID)
		}
		key := make([]byte, len(pub))
		copy(key, pub)
		keys[instanceID+":k1"] = key
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load sdk public keys: %w", err)
	}
	return keys, nil
}

func verifyEventSignature(
	ctx context.Context,
	db *sql.DB,
	ev ExecutionEvent,
	digest []byte,
) error {
	pub, err := lookupPublicKey(ctx, db, ev.TenantID, ev.InstanceID)
	if err != nil {
		return err
	}
	sigBytes, err := base64.StdEncoding.DecodeString(ev.Signature.Value)
	if err != nil {
		return fmt.Errorf("%w: decode signature: %v", ErrInvalidRequest, err)
	}
	if !ed25519.Verify(pub, digest, sigBytes) {
		return ErrSignatureVerification
	}
	return nil
}

// BootstrapLocalRegistry ensures the local tenant exists and registers the
// Node SDK keypair from ~/.intentproof/sdk-node/keypair.json when present.
// The same instance is registered for LocalTenantID and tnt_default so the
// SDK works without extra tenant configuration.
func BootstrapLocalRegistry(ctx context.Context, db *sql.DB, homeDir string) error {
	if err := EnsureTenant(ctx, db, LocalTenantID); err != nil {
		return err
	}
	keyPath := filepath.Join(homeDir, ".intentproof", "sdk-node", "keypair.json")
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read sdk keypair: %w", err)
	}
	var kp sdkKeypairFile
	if err := json.Unmarshal(raw, &kp); err != nil {
		return fmt.Errorf("parse sdk keypair: %w", err)
	}
	if kp.InstanceID == "" || kp.PrivateKey == "" {
		return fmt.Errorf("parse sdk keypair: missing instanceId or privateKey")
	}
	seed, err := base64.StdEncoding.DecodeString(kp.PrivateKey)
	if err != nil {
		return fmt.Errorf("decode sdk private key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("decode sdk private key: want %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	for _, tenantID := range []string{LocalTenantID, "tnt_default"} {
		if err := RegisterSDKInstance(ctx, db, tenantID, kp.InstanceID, pub); err != nil {
			return err
		}
	}
	return nil
}

// SignExecutionEvent attaches an Ed25519 signature over the JCS canonical
// body (signature field cleared), matching hosted ingest verification.
func SignExecutionEvent(ev ExecutionEvent, priv ed25519.PrivateKey) (ExecutionEvent, error) {
	canonical, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		return ExecutionEvent{}, err
	}
	d := sha256Sum(canonical)
	sig := ed25519.Sign(priv, d[:])
	ev.Signature = Signature{
		Alg:   "ed25519",
		KeyID: ev.InstanceID + ":k1",
		Value: base64.StdEncoding.EncodeToString(sig),
	}
	return ev, nil
}

func sha256Sum(b []byte) [32]byte {
	return sha256.Sum256(b)
}
