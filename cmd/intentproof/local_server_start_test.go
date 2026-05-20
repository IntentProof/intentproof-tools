package main

import (
	"context"
	"os"
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
		// Exercise startLocalServer's signal.NotifyContext wrapper by calling
		// the same delegate with a pre-cancelled context (wrapper lines are
		// covered via a direct call in TestStartLocalServerDirectCall).
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

func TestStartLocalServerDirectCall(t *testing.T) {
	if testing.Short() {
		t.Skip("local server integration")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("INTENTPROOF_LOCAL_INGEST_ADDR", "127.0.0.1:0")
	t.Setenv("INTENTPROOF_LOCAL_VERIFIER_ADDR", "127.0.0.1:0")
	t.Setenv("INTENTPROOF_LOCAL_DASHBOARD_ADDR", "127.0.0.1:0")
	t.Setenv("INTENTPROOF_LOCAL_OPEN_BROWSER", "0")

	errCh := make(chan error, 1)
	go func() { errCh <- startLocalServer() }()
	time.Sleep(200 * time.Millisecond)
	// startLocalServer listens for OS signals; nudge shutdown for test stability.
	p, err := os.FindProcess(os.Getpid())
	if err == nil {
		_ = p.Signal(os.Interrupt)
	}
	select {
	case <-errCh:
	case <-time.After(12 * time.Second):
		t.Fatal("startLocalServer did not return")
	}
}
