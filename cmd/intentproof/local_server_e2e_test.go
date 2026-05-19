package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestStartLocalServerWithContext(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("INTENTPROOF_LOCAL_OPEN_BROWSER", "0")

	ingestPort := freePort(t)
	verifierPort := freePort(t)
	dashboardPort := freePort(t)
	t.Setenv("INTENTPROOF_LOCAL_INGEST_ADDR", fmt.Sprintf("127.0.0.1:%d", ingestPort))
	t.Setenv("INTENTPROOF_LOCAL_VERIFIER_ADDR", fmt.Sprintf("127.0.0.1:%d", verifierPort))
	t.Setenv("INTENTPROOF_LOCAL_DASHBOARD_ADDR", fmt.Sprintf("127.0.0.1:%d", dashboardPort))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- startLocalServerWithContext(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("startLocalServerWithContext: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("startLocalServerWithContext did not exit after cancel")
		}
	})

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", ingestPort))
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				cancel()
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("local stack did not become ready")
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}
