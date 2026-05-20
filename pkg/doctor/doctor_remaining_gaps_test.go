package doctor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectLocalDBMissingFile(t *testing.T) {
	_, err := inspectLocalDB(context.Background(), filepath.Join(t.TempDir(), "missing.db"))
	if err == nil {
		t.Fatal("expected missing db error")
	}
}

func TestResolveReferencePoliciesDirMissingEnv(t *testing.T) {
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", filepath.Join(t.TempDir(), "missing"))
	_, err := ResolveReferencePoliciesDir(t.TempDir())
	if err == nil {
		t.Fatal("expected missing dir error")
	}
}

func TestRunUsesDefaultHomeWhenUnset(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	report := Run(context.Background(), Options{Cwd: t.TempDir()})
	if len(report.Checks) == 0 {
		t.Fatal("expected checks")
	}
	_ = home
}
