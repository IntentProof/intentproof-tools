package localloop

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestIngestRejectsInvalidEvent(t *testing.T) {
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

	srv := httptest.NewServer(NewIngestServer("", db, nw).Handler())
	defer srv.Close()

	body := []byte(`{"schema":"wrong","event_id":"e1"}`)
	resp, err := http.Post(srv.URL+"/v1/events", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestStoreEventChainConflictBadPrevHash(t *testing.T) {
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
	if err := RegisterSDKInstance(context.Background(), db, "tnt_x", "inst_x", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}

	ev := mustSignedEvent(t, priv, "tnt_x", "inst_x", "corr_x", 1, "sha256:0101010101010101010101010101010101010101010101010101010101010101", "a")
	digest, err := EventChainDigest(ev)
	if err != nil {
		t.Fatal(err)
	}
	_, err = StoreEvent(context.Background(), db, ev, digest[:])
	if err == nil {
		t.Fatal("expected chain conflict for bad sentinel")
	}
}

func TestValidateTenantID(t *testing.T) {
	if err := validateTenantID(""); err == nil {
		t.Fatal("expected error")
	}
	if err := validateTenantID("tnt_ok"); err != nil {
		t.Fatal(err)
	}
}

func TestReduceFlowModeAndModeRank(t *testing.T) {
	if got := reduceFlowMode([]string{modeFull, modeMinimal, modeOperational}); got != modeMinimal {
		t.Fatalf("got %s", got)
	}
	if modeRank("unknown") != 1 {
		t.Fatal("default rank")
	}
}
