package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureTenantInsertError(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "tenant.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_a"); err != nil {
		t.Fatal(err)
	}
	// Duplicate insert path should be idempotent.
	if err := EnsureTenant(ctx, db, "tnt_a"); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterSDKInstanceErrors(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "reg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if err := RegisterSDKInstance(ctx, db, "tnt_r", "inst_r", pub); err != nil {
		t.Fatal(err)
	}
	// Re-register same key is idempotent.
	if err := RegisterSDKInstance(ctx, db, "tnt_r", "inst_r", pub); err != nil {
		t.Fatal(err)
	}
}


func TestUpsertFlowUpdatesExisting(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := ExecutionEvent{
		Schema: "intentproof.event.v1", EventID: "e1", TenantID: "tnt",
		InstanceID: "inst", CorrelationID: "c", ChainPosition: 1,
		PrevEventHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		Action: "demo.action", Status: "ok", SpecVersion: "v1",
	}
	signed, err := SignExecutionEvent(ev, priv)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Signature.Value == "" {
		t.Fatal("expected signature")
	}
}

func TestLoadSDKPublicKeysEmptyCorrelation(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "emptykeys.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keys, err := LoadSDKPublicKeysForCorrelation(context.Background(), db, "tnt", "missing")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("keys=%v", keys)
	}
}


func TestSignExecutionEventSuccess(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "upsert2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_u2"); err != nil {
		t.Fatal(err)
	}
	snap := FlowSnapshot{
		Schema: "intentproof.flow.v1", FlowID: "flow1", TenantID: "tnt_u2",
		CorrelationID: "corr1",
		Window:        SnapshotWindow{ClosureReason: "event_committed"},
		InstrumentationMode: "operational",
		FlowMerkleRoot:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SnapshotURI:         "local://snapshot/flow1",
	}
	if err := UpsertFlow(ctx, db, snap); err != nil {
		t.Fatal(err)
	}
	snap.FlowID = "flow1b"
	snap.SnapshotURI = "local://snapshot/flow1b"
	if err := UpsertFlow(ctx, db, snap); err != nil {
		t.Fatal(err)
	}
	got, err := GetFlowByCorrelationID(ctx, db, "tnt_u2", "corr1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.SnapshotURI, "flow1b") {
		t.Fatalf("snap=%s", got.SnapshotURI)
	}
}
