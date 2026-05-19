package localloop

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestRunLocalDevLoopIngestAndDashboard(t *testing.T) {
	home := t.TempDir()
	ingestPort := freeTCPPort(t)
	verifierPort := freeTCPPort(t)
	dashboardPort := freeTCPPort(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	cfg := LocalDevConfig{
		HomeDir:       home,
		IngestAddr:    fmt.Sprintf("127.0.0.1:%d", ingestPort),
		VerifierAddr:  fmt.Sprintf("127.0.0.1:%d", verifierPort),
		DashboardAddr: fmt.Sprintf("127.0.0.1:%d", dashboardPort),
		OpenBrowser:   false,
	}

	dashboardBase := fmt.Sprintf("http://127.0.0.1:%d", dashboardPort)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = RunLocalDevLoop(ctx, cfg)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("RunLocalDevLoop did not exit after cancel")
			return
		}
		client := &http.Client{Timeout: 500 * time.Millisecond}
		resp, err := client.Get(dashboardBase + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			t.Errorf("dashboard still serving after shutdown: status=%d", resp.StatusCode)
		}
	})

	client := &http.Client{Timeout: 2 * time.Second}
	ingestBase := fmt.Sprintf("http://127.0.0.1:%d", ingestPort)
	verifierBase := fmt.Sprintf("http://127.0.0.1:%d", verifierPort)

	waitHTTP200(t, client, ingestBase+"/healthz")
	waitHTTP200(t, client, verifierBase+"/healthz")
	waitHTTP200(t, client, dashboardBase+"/healthz")

	db := waitOpenDB(t, filepath.Join(home, ".intentproof", "local", "local.db"))
	defer db.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterSDKInstance(context.Background(), db, LocalTenantID, "inst_stack", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}

	ev := mustSignedEvent(t, priv, LocalTenantID, "inst_stack", "corr_stack", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000", "stack.action")
	body, _ := json.Marshal(ev)
	resp, err := http.Post(ingestBase+"/v1/events", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("ingest status=%d", resp.StatusCode)
	}

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		dresp, err := client.Get(dashboardBase + "/")
		if err == nil {
			b, _ := io.ReadAll(dresp.Body)
			_ = dresp.Body.Close()
			if dresp.StatusCode == http.StatusOK && bytes.Contains(b, []byte("corr_stack")) {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("dashboard never showed correlation")
}

func TestRunLocalDevLoopExitsOnServerError(t *testing.T) {
	home := t.TempDir()
	ingestPort := freeTCPPort(t)
	verifierPort := freeTCPPort(t)
	dashboardPort := freeTCPPort(t)

	// Occupy the ingest port so ListenAndServe fails immediately.
	occupied, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", ingestPort))
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	ctx := context.Background()
	cfg := LocalDevConfig{
		HomeDir:       home,
		IngestAddr:    fmt.Sprintf("127.0.0.1:%d", ingestPort),
		VerifierAddr:  fmt.Sprintf("127.0.0.1:%d", verifierPort),
		DashboardAddr: fmt.Sprintf("127.0.0.1:%d", dashboardPort),
		OpenBrowser:   false,
	}

	done := make(chan error, 1)
	go func() {
		done <- RunLocalDevLoop(ctx, cfg)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error when ingest port is occupied")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunLocalDevLoop hung after server start failure")
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func waitHTTP200(t *testing.T, client *http.Client, url string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("endpoint not ready: %s", url)
}

func waitOpenDB(t *testing.T, dbPath string) *sql.DB {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		db, err := OpenDB(dbPath)
		if err == nil {
			return db
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("db not ready at %s", dbPath)
	return nil
}
