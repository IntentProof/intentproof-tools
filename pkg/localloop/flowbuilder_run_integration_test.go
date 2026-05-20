package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"
)

func TestFlowBuilderRunProcessesCommittedEvent(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "fb_run_int.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = NewFlowBuilder(db, nw).Run(ctx) }()

	tenant := LocalTenantID
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterSDKInstance(ctx, db, tenant, "inst_run", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}

	sentinel := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	ev := mustSignedEvent(t, priv, tenant, "inst_run", "corr_run", 1, sentinel, "demo.action")
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	if _, err := StoreEvent(ctx, db, ev, h[:]); err != nil {
		t.Fatal(err)
	}

	if err := nw.PublishEventCommitted(CommitEnvelope{
		TenantID:      tenant,
		EventID:       ev.EventID,
		CorrelationID: ev.CorrelationID,
	}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, err := GetFlowByCorrelationID(ctx, db, tenant, "corr_run")
		if err == nil && got.FlowID != "" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("flow was not materialized")
}
