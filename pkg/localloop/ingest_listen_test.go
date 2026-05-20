package localloop

import (
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestIngestListenAndServe(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "listen.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	ingest := &IngestServer{Addr: addr, DB: db}
	errCh := make(chan error, 1)
	go func() {
		errCh <- ingest.ListenAndServe()
	}()

	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://" + addr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("server did not become ready")
}
