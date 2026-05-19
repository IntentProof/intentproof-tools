package doctor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveIngestURL(t *testing.T) {
	t.Setenv("INTENTPROOF_INGEST_URL", "http://example.com:9787")
	t.Setenv("INTENTPROOF_USE_LOCAL_INGEST", "")
	url, source := ResolveIngestURL()
	if url != "http://example.com:9787/v1/events" || source != "INTENTPROOF_INGEST_URL" {
		t.Fatalf("got %q %q", url, source)
	}
}

func TestResolveIngestURLLocalFlag(t *testing.T) {
	t.Setenv("INTENTPROOF_INGEST_URL", "")
	t.Setenv("INTENTPROOF_USE_LOCAL_INGEST", "1")
	url, source := ResolveIngestURL()
	if url != defaultLocalIngestEventsURL || source != "INTENTPROOF_USE_LOCAL_INGEST" {
		t.Fatalf("got %q %q", url, source)
	}
}

func TestAdvisePresetEmpty(t *testing.T) {
	advice := advisePreset(nil)
	if advice.Status != StatusSkip {
		t.Fatalf("status %s", advice.Status)
	}
}

func TestAdvisePresetDemoActionsMatchNotificationPreset(t *testing.T) {
	observed := map[string]struct{}{
		"payments.refund.execute": {},
		"ledger.entry.write":      {},
		"customer.notify":         {},
	}
	advice := advisePreset(observed)
	if advice.Status != StatusOK || !strings.Contains(advice.Summary, "refund-with-notification") {
		t.Fatalf("got %+v", advice)
	}
}

func TestIngestURLsEquivalentLocalhostAndLoopback(t *testing.T) {
	if !ingestURLsEquivalent("http://127.0.0.1:9787/v1/events", "http://localhost:9787/v1/events") {
		t.Fatal("expected localhost and 127.0.0.1 to match")
	}
}

func TestAdvisePresetFullRefundNotification(t *testing.T) {
	observed := map[string]struct{}{
		"payments.refund.execute": {},
		"ledger.refund.record":    {},
		"customer.notify.refund":  {},
	}
	advice := advisePreset(observed)
	if advice.Status != StatusOK || !strings.Contains(advice.Summary, "refund-with-notification") {
		t.Fatalf("got %+v", advice)
	}
}

func TestAdvisePresetPartial(t *testing.T) {
	observed := map[string]struct{}{
		"payments.refund.execute": {},
	}
	advice := advisePreset(observed)
	if advice.Status != StatusOK || !strings.Contains(advice.Summary, "refund-basic") {
		t.Fatalf("got %+v", advice)
	}
}

func TestAdvisePresetMissingRefundExecute(t *testing.T) {
	observed := map[string]struct{}{
		"ledger.refund.record": {},
	}
	advice := advisePreset(observed)
	if advice.Status != StatusWarn || !strings.Contains(advice.Hint, "payments.refund.execute") {
		t.Fatalf("got %+v", advice)
	}
}

func TestRunLocalLoopReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	t.Setenv("INTENTPROOF_INGEST_URL", srv.URL+"/v1/events")
	t.Setenv("INTENTPROOF_LOCAL_INGEST_ADDR", strings.TrimPrefix(srv.URL, "http://"))
	t.Setenv("INTENTPROOF_LOCAL_VERIFIER_ADDR", strings.TrimPrefix(srv.URL, "http://"))
	t.Setenv("INTENTPROOF_LOCAL_DASHBOARD_ADDR", strings.TrimPrefix(srv.URL, "http://"))

	home := t.TempDir()
	report := Run(context.Background(), Options{
		HomeDir: home,
		Cwd:     t.TempDir(),
		Client:  srv.Client(),
	})

	foundIngest := false
	for _, c := range report.Checks {
		if c.Name == "local ingest" && c.Status == StatusOK {
			foundIngest = true
		}
	}
	if !foundIngest {
		t.Fatalf("expected reachable ingest, got %+v", report.Checks)
	}
}

func TestRunReferencePoliciesFromWorkspace(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// pkg/doctor -> intentproof-tools -> workspace root with intentproof-spec.
	root := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	specDir := filepath.Join(root, "intentproof-spec", "reference-policies")
	if _, err := os.Stat(specDir); err != nil {
		t.Skip("intentproof-spec reference-policies not present:", err)
	}

	report := Run(context.Background(), Options{
		HomeDir: t.TempDir(),
		Cwd:     filepath.Join(root, "intentproof-tools"),
	})
	for _, c := range report.Checks {
		if c.Name == "reference policies" && c.Status == StatusOK {
			return
		}
	}
	t.Fatalf("expected reference policies ok, got %+v", report.Checks)
}

func TestFormatAgentMarkdownIncludesChecks(t *testing.T) {
	r := Report{Checks: []Check{{
		Name: "sdk ingest", Status: StatusOK, Detail: "configured",
	}}}
	out := FormatAgentMarkdown(r)
	if !strings.Contains(out, "# IntentProof doctor report") || !strings.Contains(out, "sdk ingest") {
		t.Fatalf("out=%q", out)
	}
}

func TestRunFreshMachineLocalLoopWarnsOnly(t *testing.T) {
	t.Setenv("INTENTPROOF_INGEST_URL", "")
	t.Setenv("INTENTPROOF_USE_LOCAL_INGEST", "")

	home := t.TempDir()
	report := Run(context.Background(), Options{
		HomeDir: home,
		Cwd:     t.TempDir(),
		Client:  &http.Client{Timeout: 100 * time.Millisecond},
	})
	if report.HasFailures() {
		t.Fatalf("fresh machine should not fail doctor, got %+v", report.Checks)
	}
	for _, c := range report.Checks {
		if c.Name == "local ingest" && c.Status != StatusWarn {
			t.Fatalf("expected local ingest warn, got %+v", c)
		}
	}
}

func TestFormatReportMarksFailures(t *testing.T) {
	r := Report{Checks: []Check{{
		Name: "local ingest", Status: StatusFail, Detail: "down",
	}}}
	out := FormatReport(r)
	if !strings.Contains(out, "[fail]") || !r.HasFailures() {
		t.Fatalf("out=%q failures=%v", out, r.HasFailures())
	}
}
