package localloop

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestIngestAcceptsChainedEventsAndMaterializesFlow(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "local.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go func() { _ = NewFlowBuilder(db, nw).Run(ctx) }()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterSDKInstance(ctx, db, "tnt_flow", "inst_flow", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(NewIngestServer("", db, nw).Handler())
	defer srv.Close()

	ev1 := mustSignedEvent(t, priv, "tnt_flow", "inst_flow", "corr_flow2", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000", "flow.action")
	b1, _ := json.Marshal(ev1)
	resp1, err := http.Post(srv.URL+"/v1/events", "application/json", bytes.NewReader(b1))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp1.Body.Close()

	d1, _ := EventChainDigest(ev1)
	prev := FormatChainHash(d1)
	ev2 := mustSignedEvent(t, priv, "tnt_flow", "inst_flow", "corr_flow2", 2, prev, "flow.action2")
	b2, _ := json.Marshal(ev2)
	resp2, err := http.Post(srv.URL+"/v1/events", "application/json", bytes.NewReader(b2))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		flow, err := GetFlowByCorrelationID(ctx, db, "tnt_flow", "corr_flow2")
		if err == nil && flow != nil {
			_, _, mode, err := FlowBoundsAndMode(ctx, db, "tnt_flow", "corr_flow2")
			if err == nil && mode != "" {
				flowJSON, err := BuildVerifierFlowJSON(ctx, db, "tnt_flow", "corr_flow2")
				if err != nil {
					t.Fatalf("BuildVerifierFlowJSON: %v", err)
				}
				if len(flowJSON) == 0 {
					t.Fatal("empty flow json")
				}
				jsonl, err := LoadEventsJSONL(ctx, db, "tnt_flow", "corr_flow2")
				if err != nil || len(jsonl) == 0 {
					t.Fatalf("LoadEventsJSONL: %v len=%d", err, len(jsonl))
				}
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("flow not materialized")
}

func TestStoreEventIdempotentReplay(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "local.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := mustSignedEvent(t, priv, "tnt_x", "inst_x", "corr_idem", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000", "a")
	digest, err := EventChainDigest(ev)
	if err != nil {
		t.Fatal(err)
	}
	inserted, err := StoreEvent(context.Background(), db, ev, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if !inserted {
		t.Fatal("expected insert")
	}
	inserted2, err := StoreEvent(context.Background(), db, ev, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if inserted2 {
		t.Fatal("expected idempotent replay")
	}
}
