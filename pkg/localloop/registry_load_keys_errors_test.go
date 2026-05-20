package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadSDKPublicKeysForCorrelationRejectsInvalidKeyLength(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "loadkeys.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	tenant := "tnt_lk"
	instance := "inst_bad"
	if err := EnsureTenant(ctx, db, tenant); err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO sdk_instances (tenant_id, instance_id, public_key, registered_at, revoked_at)
VALUES (?, ?, ?, ?, NULL)`,
		tenant, instance, []byte("short"), "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := mustSignedEvent(t, priv, tenant, instance, "corr_lk", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000", "act")
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	_, err = db.ExecContext(ctx, `
INSERT INTO execution_events (
  tenant_id, event_id, correlation_id, instance_id, chain_position,
  prev_event_hash, event_hash, action, status, started_at, completed_at,
  duration_ms, spec_version, body, signature
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		tenant, ev.EventID, ev.CorrelationID, instance, 1, ev.PrevEventHash, h[:],
		ev.Action, ev.Status, ev.StartedAt.Format(time.RFC3339Nano),
		ev.CompletedAt.Format(time.RFC3339Nano),
		ev.DurationMS, ev.SpecVersion, "{}", "{}")
	if err != nil {
		t.Fatal(err)
	}

	_, err = LoadSDKPublicKeysForCorrelation(ctx, db, tenant, "corr_lk")
	if err == nil || !strings.Contains(err.Error(), "invalid public key length") {
		t.Fatalf("err=%v", err)
	}
}
