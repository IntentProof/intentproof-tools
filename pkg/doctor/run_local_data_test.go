package doctor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRunWithLocalDataAndProbeOK(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".intentproof", "local")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Join(home, ".intentproof", "sdk-node")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(SDKKeypairPath(home), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("INTENTPROOF_INGEST_URL", srv.URL)
	t.Setenv("INTENTPROOF_USE_LOCAL_INGEST", "")

	report := Run(context.Background(), Options{HomeDir: home, Cwd: home, Client: srv.Client()})
	if report.HasFailures() {
		for _, c := range report.Checks {
			if c.Status == StatusFail {
				t.Fatalf("check %q: %s", c.Name, c.Detail)
			}
		}
	}
}

func TestCheckLocalDataStatErrors(t *testing.T) {
	home := t.TempDir()
	blocker := filepath.Join(home, ".intentproof")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	checks := checkLocalData(context.Background(), home)
	found := false
	for _, c := range checks {
		if c.Name == "local data" && c.Status == StatusFail {
			found = true
		}
	}
	if !found {
		t.Fatalf("checks=%+v", checks)
	}
}
