package localloop

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestIngestRejectsOversizedBody(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "bigbody.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	srv := httptest.NewServer(NewIngestServer("", db, nil).Handler())
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/events", io.NopCloser(bytes.NewReader(make([]byte, 1<<20+1))))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestIngestRejectsUnreadableBody(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "readerr.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	srv := NewIngestServer("", db, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/events", io.NopCloser(errReader{}))
	srv.handleV1Events(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestIngestReturns500WhenNATSPublishFails(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "natspub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tnt_natsfail"
	if err := RegisterSDKInstance(ctx, db, tenant, "inst_nf", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}

	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	nw.Shutdown()

	srv := httptest.NewServer(NewIngestServer("", db, nw).Handler())
	defer srv.Close()

	ev := mustSignedEvent(t, priv, tenant, "inst_nf", "corr_nf", 1,
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

func TestIngestReturns400ForInvalidSignatureEncoding(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "badsig.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tnt_badsig"
	if err := RegisterSDKInstance(ctx, db, tenant, "inst_bs", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(NewIngestServer("", db, nil).Handler())
	defer srv.Close()

	ev := mustSignedEvent(t, priv, tenant, "inst_bs", "corr_bs", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"demo.action")
	ev.Signature.Value = "!!!not-base64!!!"
	body, _ := json.Marshal(ev)
	resp, err := http.Post(srv.URL+"/v1/events", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}
