package doctor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunWithMockLocalLoop(t *testing.T) {
	health := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	ingest := httptest.NewServer(health)
	verifier := httptest.NewServer(health)
	dashboard := httptest.NewServer(health)
	t.Cleanup(ingest.Close)
	t.Cleanup(verifier.Close)
	t.Cleanup(dashboard.Close)

	t.Setenv("INTENTPROOF_USE_LOCAL_INGEST", "1")
	t.Setenv("INTENTPROOF_LOCAL_INGEST_ADDR", hostPort(t, ingest.URL))
	t.Setenv("INTENTPROOF_LOCAL_VERIFIER_ADDR", hostPort(t, verifier.URL))
	t.Setenv("INTENTPROOF_LOCAL_DASHBOARD_ADDR", hostPort(t, dashboard.URL))
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", filepath.Join(t.TempDir(), "refs"))

	home := t.TempDir()
	report := Run(context.Background(), Options{
		HomeDir: home,
		Cwd:     t.TempDir(),
		Client:  &http.Client{Timeout: 2 * http.DefaultClient.Timeout},
	})
	out := FormatReport(report)
	if !strings.Contains(out, "IntentProof doctor") {
		t.Fatalf("report=%s", out)
	}
	if len(report.Checks) == 0 {
		t.Fatal("expected checks")
	}
}

func hostPort(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}
