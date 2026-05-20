package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestFlowBuilderHandlePublishFlowError(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "fb_pub.db"))
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
	tenant := "bad*tenant"
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterSDKInstance(ctx, db, tenant, "inst_pub", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}

	sentinel := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	ev := mustSignedEvent(t, priv, tenant, "inst_pub", "corr_pub", 1, sentinel, "demo.action")
	canon, _ := canonicalizeWithoutSignature(ev)
	h := sha256.Sum256(canon)
	if _, err := StoreEvent(ctx, db, ev, h[:]); err != nil {
		t.Fatal(err)
	}

	fb := NewFlowBuilder(db, nw)
	env := CommitEnvelope{TenantID: tenant, EventID: ev.EventID, CorrelationID: ev.CorrelationID}
	raw, _ := json.Marshal(env)
	if err := fb.handle(ctx, raw); err == nil {
		t.Fatal("expected publish error")
	}
}
