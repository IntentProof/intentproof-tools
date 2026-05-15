package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/intentproof/intentproof-tools/pkg/localloop"
)

func startLocalServer() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("home dir: %w", err)
	}
	dataDir := filepath.Join(home, ".intentproof", "local")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	dbPath := filepath.Join(dataDir, "local.db")
	db, err := localloop.OpenDB(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	if err := localloop.BootstrapLocalRegistry(context.Background(), db, home); err != nil {
		return fmt.Errorf("bootstrap local sdk registry: %w", err)
	}

	nats, err := localloop.StartEmbeddedNATS(dataDir)
	if err != nil {
		return fmt.Errorf("start nats: %w", err)
	}
	defer nats.Shutdown()

	ingestAddr := ":9787"
	if v := os.Getenv("INTENTPROOF_LOCAL_INGEST_ADDR"); v != "" {
		ingestAddr = v
	}
	var ingestURL string
	switch {
	case len(ingestAddr) > 0 && ingestAddr[0] == ':':
		ingestURL = "http://localhost" + ingestAddr
	case len(ingestAddr) > 7 && (ingestAddr[:7] == "http://" || ingestAddr[:8] == "https://"):
		ingestURL = ingestAddr
	default:
		ingestURL = "http://" + ingestAddr
	}

	ingestSrv := localloop.NewIngestServer(ingestAddr, db, nats)
	flowBuilder := localloop.NewFlowBuilder(db, nats)

	fmt.Println("data dir:", dataDir)
	fmt.Println("migrating SQLite")
	fmt.Println("generating local tenant: tnt_local")
	fmt.Println("starting ingest    on", ingestAddr)
	fmt.Println("starting flow builder")
	fmt.Println("NATS URL:", nats.URL())
	fmt.Println()
	fmt.Println("Ingest endpoint:", ingestURL+"/v1/events")
	fmt.Println("NATS endpoint:  ", nats.URL())
	fmt.Println("\nWhen you run code with INTENTPROOF_INGEST_URL=" + ingestURL + "/v1/events,")
	fmt.Println("events flow in real-time. Ctrl-C to stop.")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)

	// Start ingest HTTP server in background.
	go func() {
		if err := ingestSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("ingest server: %w", err)
		}
	}()

	// Start flow builder in background.
	go func() {
		if err := flowBuilder.Run(ctx); err != nil && err != context.Canceled {
			errCh <- fmt.Errorf("flow builder: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		fmt.Println("\nShutting down...")
		return nil
	case err := <-errCh:
		fmt.Println("\nShutting down after error...")
		return err
	}
}
