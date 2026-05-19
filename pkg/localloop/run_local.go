package localloop

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

// LocalDevConfig configures the local ingest, verifier, dashboard, and flow builder.
type LocalDevConfig struct {
	HomeDir       string
	DataDir       string
	IngestAddr    string
	VerifierAddr  string
	DashboardAddr string
	OpenBrowser   bool
	Stdout        func(string)
}

// RunLocalDevLoop starts the local stack until ctx is canceled.
func RunLocalDevLoop(ctx context.Context, cfg LocalDevConfig) error {
	if cfg.HomeDir == "" {
		return fmt.Errorf("home dir is required")
	}
	dataDir := cfg.DataDir
	if dataDir == "" {
		dataDir = filepath.Join(cfg.HomeDir, ".intentproof", "local")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	dbPath := filepath.Join(dataDir, "local.db")
	db, err := OpenDB(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	if err := BootstrapLocalRegistry(ctx, db, cfg.HomeDir); err != nil {
		return fmt.Errorf("bootstrap local sdk registry: %w", err)
	}

	nats, err := StartEmbeddedNATS(dataDir)
	if err != nil {
		return fmt.Errorf("start nats: %w", err)
	}
	defer nats.Shutdown()

	ingestAddr := cfg.IngestAddr
	if ingestAddr == "" {
		ingestAddr = ":9787"
	}
	verifierAddr := cfg.VerifierAddr
	if verifierAddr == "" {
		verifierAddr = ":9788"
	}
	dashboardAddr := cfg.DashboardAddr
	if dashboardAddr == "" {
		dashboardAddr = ":9789"
	}

	logf := cfg.Stdout
	if logf == nil {
		logf = func(string) {}
	}
	ingestURL := LocalPublicBaseURL(ingestAddr)
	verifierURL := LocalPublicBaseURL(verifierAddr)
	dashboardURL := LocalPublicBaseURL(dashboardAddr)
	dashLinks := LocalDashboardLinks{
		IngestURL:    ingestURL,
		VerifierURL:  verifierURL,
		DashboardURL: dashboardURL,
	}

	ingestSrv := NewIngestServer(ingestAddr, db, nats)
	flowBuilder := NewFlowBuilder(db, nats)

	logf("data dir: " + dataDir)
	logf("starting ingest on " + ingestAddr)
	logf("starting verifier on " + verifierAddr)
	logf("starting dashboard on " + dashboardAddr)

	errCh := make(chan error, 4)
	ingestServer := &http.Server{Addr: ingestAddr, Handler: ingestSrv.Handler()}

	go func() {
		if err := ingestServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("ingest server: %w", err)
		}
	}()

	go func() {
		if err := http.ListenAndServe(verifierAddr, LocalVerifierHandler()); err != nil {
			errCh <- fmt.Errorf("verifier server: %w", err)
		}
	}()

	go func() {
		if err := http.ListenAndServe(dashboardAddr, LocalDashboardHandler(db, dashLinks)); err != nil {
			errCh <- fmt.Errorf("dashboard server: %w", err)
		}
	}()

	if cfg.OpenBrowser {
		MaybeOpenLocalDashboard(dashboardURL)
	}

	go func() {
		if err := flowBuilder.Run(ctx); err != nil && err != context.Canceled {
			errCh <- fmt.Errorf("flow builder: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		_ = ingestServer.Close()
		return nil
	case err := <-errCh:
		_ = ingestServer.Close()
		return err
	}
}
