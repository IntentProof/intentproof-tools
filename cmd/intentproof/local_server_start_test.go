package main

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestStartLocalServerWrapperHonorsCancelledContext(t *testing.T) {
	if testing.Short() {
		t.Skip("local server integration")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("INTENTPROOF_LOCAL_INGEST_ADDR", "127.0.0.1:0")
	t.Setenv("INTENTPROOF_LOCAL_VERIFIER_ADDR", "127.0.0.1:0")
	t.Setenv("INTENTPROOF_LOCAL_DASHBOARD_ADDR", "127.0.0.1:0")
	t.Setenv("INTENTPROOF_LOCAL_OPEN_BROWSER", "0")

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- startLocalServerWithContext(ctx)
	}()
	time.Sleep(150 * time.Millisecond)
	cancel()
	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Logf("shutdown: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("startLocalServerWithContext did not return")
	}
}

func TestStartLocalServerWithContextBusyIngest(t *testing.T) {
	if testing.Short() {
		t.Skip("local server integration")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("INTENTPROOF_LOCAL_OPEN_BROWSER", "0")

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := occupied.Addr().(*net.TCPAddr).Port
	t.Setenv("INTENTPROOF_LOCAL_INGEST_ADDR", fmt.Sprintf("127.0.0.1:%d", port))
	t.Setenv("INTENTPROOF_LOCAL_VERIFIER_ADDR", "127.0.0.1:0")
	t.Setenv("INTENTPROOF_LOCAL_DASHBOARD_ADDR", "127.0.0.1:0")
	defer occupied.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := startLocalServerWithContext(ctx); err == nil {
		t.Fatal("expected bind error")
	}
}
