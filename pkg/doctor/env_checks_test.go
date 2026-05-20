package doctor

import (
	"context"
	"testing"
)

func TestRunIncludesEnvChecksWhenSet(t *testing.T) {
	t.Setenv("INTENTPROOF_INGEST_TOKEN", "tok")
	t.Setenv("INTENTPROOF_TENANT_ID", "tnt_env")
	report := Run(context.Background(), Options{Cwd: t.TempDir()})
	foundAuth := false
	foundTenant := false
	for _, c := range report.Checks {
		if c.Name == "ingest auth" {
			foundAuth = true
		}
		if c.Name == "sdk tenant" {
			foundTenant = true
		}
	}
	if !foundAuth || !foundTenant {
		t.Fatalf("checks=%+v", report.Checks)
	}
}

func TestCheckLocalDataMissingDir(t *testing.T) {
	checks := checkLocalData(context.Background(), t.TempDir())
	if len(checks) == 0 {
		t.Fatal("expected checks")
	}
}
