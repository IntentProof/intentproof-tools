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
	dataDir := filepath.Join(os.Getenv("HOME"), ".intentproof", "local")
	_ = os.MkdirAll(dataDir, 0o755)

	dbPath := filepath.Join(dataDir, "local.db")
	db, err := localloop.OpenDB(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	nats, err := localloop.StartEmbeddedNATS()
	if err != nil {
		return fmt.Errorf("start nats: %w", err)
	}
	defer nats.Shutdown()

	ingestAddr := ":9786"
	if v := os.Getenv("INTENTPROOF_LOCAL_INGEST_ADDR"); v != "" {
		ingestAddr = v
	}
	ingestURL := "http://localhost" + ingestAddr
	if ingestAddr[0] == ':' {
		ingestURL = "http://localhost" + ingestAddr
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
	fmt.Println("Ingest endpoint:", ingestURL)
	fmt.Println("NATS endpoint:  ", nats.URL())
	fmt.Println("\nWhen you run code with INTENTPROOF_INGEST_URL="+ingestURL+",")
	fmt.Println("events flow in real-time. Ctrl-C to stop.")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start ingest HTTP server in background.
	go func() {
		if err := ingestSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "ingest server error: %v\n", err)
		}
	}()

	// Start flow builder in background.
	go func() {
		if err := flowBuilder.Run(ctx); err != nil && err != context.Canceled {
			fmt.Fprintf(os.Stderr, "flow builder error: %v\n", err)
		}
	}()

	<-ctx.Done()
	fmt.Println("\nShutting down...")
	return nil
}
