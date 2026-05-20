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
)

func TestIngestReturns500WhenDBClosed(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "closed.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tnt_db"
	if err := RegisterSDKInstance(ctx, db, tenant, "inst_db", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(NewIngestServer("", db, nil).Handler())
	defer srv.Close()

	ev := mustSignedEvent(t, priv, tenant, "inst_db", "corr_db", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"demo.action")
	body, _ := json.Marshal(ev)
	resp, err := http.Post(srv.URL+"/v1/events", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}
