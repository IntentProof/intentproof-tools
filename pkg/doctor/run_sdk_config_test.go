package doctor

import (
	"context"
	"os"
	"testing"
)

func TestRunWarnsWhenRemoteIngestWithoutToken(t *testing.T) {
	t.Setenv("INTENTPROOF_USE_LOCAL_INGEST", "")
	t.Setenv("INTENTPROOF_INGEST_URL", "https://ingest.example.com")
	t.Setenv("INTENTPROOF_INGEST_TOKEN", "")
	t.Setenv("INTENTPROOF_TENANT_ID", "tnt_doc")

	report := Run(context.Background(), Options{
		HomeDir: t.TempDir(),
		Cwd:     t.TempDir(),
	})
	foundIngest := false
	foundTenant := false
	for _, c := range report.Checks {
		if c.Name == "ingest auth" && c.Status == StatusWarn {
			foundIngest = true
		}
		if c.Name == "sdk tenant" && c.Status == StatusOK {
			foundTenant = true
		}
	}
	if !foundIngest || !foundTenant {
		t.Fatalf("checks=%+v", report.Checks)
	}
}

func TestRunReportsIngestTokenWhenSet(t *testing.T) {
	t.Setenv("INTENTPROOF_USE_LOCAL_INGEST", "")
	t.Setenv("INTENTPROOF_INGEST_URL", "https://ingest.example.com")
	t.Setenv("INTENTPROOF_INGEST_TOKEN", "secret")

	report := Run(context.Background(), Options{
		HomeDir: t.TempDir(),
		Cwd:     t.TempDir(),
	})
	found := false
	for _, c := range report.Checks {
		if c.Name == "ingest auth" && c.Status == StatusOK && c.Detail == "INTENTPROOF_INGEST_TOKEN is set" {
			found = true
		}
	}
	if !found {
		t.Fatalf("checks=%+v", report.Checks)
	}
	_ = os.Getenv("INTENTPROOF_INGEST_TOKEN")
}
