package localloop

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
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

	servers := []*http.Server{
		{Addr: ingestAddr, Handler: ingestSrv.Handler()},
		{Addr: verifierAddr, Handler: LocalVerifierHandler()},
		{Addr: dashboardAddr, Handler: LocalDashboardHandler(db, dashLinks)},
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(servers)+1)
	for _, srv := range servers {
		wg.Add(1)
		go func(server *http.Server) {
			defer wg.Done()
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errCh <- err
			}
		}(srv)
	}

	flowDone := make(chan struct{})
	go func() {
		defer close(flowDone)
		if err := flowBuilder.Run(ctx); err != nil && err != context.Canceled {
			errCh <- fmt.Errorf("flow builder: %w", err)
		}
	}()

	if cfg.OpenBrowser {
		MaybeOpenLocalDashboard(dashboardURL)
	}

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdownCtx)
	}
	wg.Wait()
	<-flowDone

	if runErr != nil {
		return runErr
	}
	return nil
}
