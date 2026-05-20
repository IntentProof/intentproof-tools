package doctor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/localloop"
)

func TestInspectLocalDBWithStoredEvents(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "local.db")
	db, err := localloop.OpenDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenant := localloop.LocalTenantID
	if err := localloop.EnsureTenant(ctx, db, tenant); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := localloop.RegisterSDKInstance(ctx, db, tenant, "inst_doc", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC)
	ev := localloop.ExecutionEvent{
		Schema:        "intentproof.event.v1",
		EventID:       "evt_doc_1",
		TenantID:      tenant,
		InstanceID:    "inst_doc",
		CorrelationID: "corr_doc",
		PrevEventHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		ChainPosition: 1,
		Intent:        "doc",
		Action:        "payments.refund.execute",
		Status:        "ok",
		StartedAt:     now,
		CompletedAt:   now.Add(time.Second),
		DurationMS:    1000,
		Inputs:        []any{},
		Output:        map[string]any{},
		SpecVersion:   "1.0.0",
		SDKVersion:    "test",
		Attributes:    map[string]any{},
	}
	signed, err := localloop.SignExecutionEvent(ev, priv)
	if err != nil {
		t.Fatal(err)
	}
	dig, err := localloop.EventChainDigest(signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := localloop.StoreEvent(ctx, db, signed, dig[:]); err != nil {
		t.Fatal(err)
	}
	db.Close()

	snap, err := inspectLocalDB(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if snap.EventCount != 1 {
		t.Fatalf("events=%d", snap.EventCount)
	}
	if snap.Actions["payments.refund.execute"] != 1 {
		t.Fatalf("actions=%v", snap.Actions)
	}
	if snap.LastEventAt == "" {
		t.Fatal("expected last event time")
	}
	_ = sha256.Sum256(dig[:])
}
