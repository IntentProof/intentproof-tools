package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/intentproof/intentproof-tools/pkg/localloop"
)

func startLocalServer() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return startLocalServerWithContext(ctx)
}

func startLocalServerWithContext(ctx context.Context) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("home dir: %w", err)
	}

	ingestAddr := ":9787"
	if v := os.Getenv("INTENTPROOF_LOCAL_INGEST_ADDR"); v != "" {
		ingestAddr = v
	}
	verifierAddr := ":9788"
	if v := os.Getenv("INTENTPROOF_LOCAL_VERIFIER_ADDR"); v != "" {
		verifierAddr = v
	}
	dashboardAddr := ":9789"
	if v := os.Getenv("INTENTPROOF_LOCAL_DASHBOARD_ADDR"); v != "" {
		dashboardAddr = v
	}

	cfg := localloop.LocalDevConfig{
		HomeDir:       home,
		IngestAddr:    ingestAddr,
		VerifierAddr:  verifierAddr,
		DashboardAddr: dashboardAddr,
		OpenBrowser:   localloop.LocalDashboardAutoOpenEnabled(),
		Stdout:        func(s string) { fmt.Println(s) },
	}

	if err := localloop.RunLocalDevLoop(ctx, cfg); err != nil {
		fmt.Println("\nShutting down after error...")
		return err
	}
	fmt.Println("\nShutting down...")
	return nil
}
