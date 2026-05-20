package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildVerifierFlowJSONIncludesAttributes(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "flow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	tenant := "tnt_flow"
	if err := EnsureTenant(ctx, db, tenant); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterSDKInstance(ctx, db, tenant, "inst_flow", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}

	sentinel := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	ev := mustSignedEvent(t, priv, tenant, "inst_flow", "corr_flow", 1, sentinel, "demo.action")
	ev.Attributes = map[string]any{"tier": "gold"}
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	if _, err := StoreEvent(ctx, db, ev, h[:]); err != nil {
		t.Fatal(err)
	}

	window := SnapshotWindow{
		OpenedAt:      ev.StartedAt,
		ClosedAt:      ev.CompletedAt,
		ClosureReason: "event_committed",
	}
	snap := FlowSnapshot{
		Schema:              "intentproof.flow.v1",
		FlowID:              "flow_corr_flow",
		TenantID:            tenant,
		CorrelationID:       "corr_flow",
		Window:              window,
		Events:              []SnapshotEvent{{EventID: ev.EventID, Ordinal: 0, Hash: FormatChainHash(h)}},
		InstrumentationMode: "operational",
		FlowMerkleRoot:      FormatChainHash(h),
		SnapshotURI:         "local://snapshot/flow_corr_flow",
	}
	if err := UpsertFlow(ctx, db, snap); err != nil {
		t.Fatal(err)
	}

	raw, err := BuildVerifierFlowJSON(ctx, db, tenant, "corr_flow")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	events, _ := doc["events"].([]any)
	if len(events) != 1 {
		t.Fatalf("events=%v", doc["events"])
	}
	ev0, _ := events[0].(map[string]any)
	attrs, _ := ev0["attributes"].(map[string]any)
	if attrs["tier"] != "gold" {
		t.Fatalf("attrs=%v", attrs)
	}
}

func TestLoadEventsJSONLReturnsBodies(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "jsonl.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	tenant := "tnt_jsonl"
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	ev := mustSignedEvent(t, priv, tenant, "inst_j", "corr_j", 1, sentinel, "demo.action")
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	if _, err := StoreEvent(ctx, db, ev, h[:]); err != nil {
		t.Fatal(err)
	}

	data, err := LoadEventsJSONL(ctx, db, tenant, "corr_j")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("empty jsonl")
	}
}

func TestFlowBoundsAndMode(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "bounds.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	tenant := "tnt_b"
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	ev := mustSignedEvent(t, priv, tenant, "inst_b", "corr_b", 1, sentinel, "demo.action")
	ev.Attributes["intentproof"] = map[string]any{"mode": modeMinimal}
	canon, _ := canonicalizeWithoutSignature(ev)
	h := sha256.Sum256(canon)
	if _, err := StoreEvent(ctx, db, ev, h[:]); err != nil {
		t.Fatal(err)
	}
	started, closed, mode, err := FlowBoundsAndMode(ctx, db, tenant, "corr_b")
	if err != nil {
		t.Fatal(err)
	}
	if started.IsZero() || closed.IsZero() {
		t.Fatal("expected bounds")
	}
	if mode != modeMinimal {
		t.Fatalf("mode=%s", mode)
	}
	_ = time.Now()
}
