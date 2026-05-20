package doctor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunHomeDirFailure(t *testing.T) {
	orig := doctorUserHomeDir
	doctorUserHomeDir = func() (string, error) {
		return "", errors.New("no home")
	}
	t.Cleanup(func() { doctorUserHomeDir = orig })

	report := Run(context.Background(), Options{Cwd: t.TempDir()})
	if len(report.Checks) != 1 || report.Checks[0].Status != StatusFail {
		t.Fatalf("checks=%+v", report.Checks)
	}
}

func TestRunWorkingDirFailure(t *testing.T) {
	orig := doctorGetwd
	doctorGetwd = func() (string, error) {
		return "", errors.New("no cwd")
	}
	t.Cleanup(func() { doctorGetwd = orig })

	report := Run(context.Background(), Options{HomeDir: t.TempDir()})
	if len(report.Checks) != 1 || report.Checks[0].Status != StatusFail {
		t.Fatalf("checks=%+v", report.Checks)
	}
}

func TestCheckLocalLoopWarnsWhenIngestURLMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	addr := srv.Listener.Addr().String()
	t.Setenv("INTENTPROOF_LOCAL_INGEST_ADDR", addr)
	t.Setenv("INTENTPROOF_LOCAL_VERIFIER_ADDR", addr)
	t.Setenv("INTENTPROOF_LOCAL_DASHBOARD_ADDR", addr)
	t.Setenv("INTENTPROOF_INGEST_URL", "")
	t.Setenv("INTENTPROOF_USE_LOCAL_INGEST", "")

	checks := checkLocalLoop(context.Background(), srv.Client())
	var found bool
	for _, c := range checks {
		if c.Name == "ingest alignment" && c.Status == StatusWarn &&
			strings.Contains(c.Detail, "SDK ingest URL is not configured") {
			found = true
		}
	}
	if !found {
		t.Fatalf("checks=%+v", checks)
	}
}

func TestCheckLocalDataInspectFailure(t *testing.T) {
	home := t.TempDir()
	dbPath := filepath.Join(LocalDataDir(home), "local.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, []byte("not sqlite"), 0o644); err != nil {
		t.Fatal(err)
	}
	checks := checkLocalData(context.Background(), home)
	var found bool
	for _, c := range checks {
		if c.Name == "local database" && c.Status == StatusFail {
			found = true
		}
	}
	if !found {
		t.Fatalf("checks=%+v", checks)
	}
}
