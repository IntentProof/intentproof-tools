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

func TestFlowBuilderHandleMaterializesFlow(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "fb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()

	ctx := context.Background()
	tenant := LocalTenantID
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterSDKInstance(ctx, db, tenant, "inst_fb", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}

	sentinel := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	ev := mustSignedEvent(t, priv, tenant, "inst_fb", "corr_fb", 1, sentinel, "demo.action")
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	if _, err := StoreEvent(ctx, db, ev, h[:]); err != nil {
		t.Fatal(err)
	}

	fb := NewFlowBuilder(db, nw)
	env := CommitEnvelope{
		TenantID:      tenant,
		EventID:       ev.EventID,
		CorrelationID: ev.CorrelationID,
	}
	raw, _ := json.Marshal(env)
	if err := fb.handle(ctx, raw); err != nil {
		t.Fatal(err)
	}

	got, err := GetFlowByCorrelationID(ctx, db, tenant, "corr_fb")
	if err != nil {
		t.Fatal(err)
	}
	if got.FlowID == "" {
		t.Fatal("expected flow")
	}
}

func TestFlowBuilderHandleValidationErrors(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "fb_err.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	fb := NewFlowBuilder(db, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := fb.handle(ctx, []byte("{")); err == nil {
		t.Fatal("expected decode error")
	}
	if err := fb.handle(ctx, []byte(`{"tenant_id":"t"}`)); err == nil {
		t.Fatal("expected missing fields error")
	}
	env := CommitEnvelope{TenantID: "t", CorrelationID: "c", EventID: "e"}
	raw, _ := json.Marshal(env)
	if err := fb.handle(ctx, raw); err == nil {
		t.Fatal("expected no events error")
	}
}
