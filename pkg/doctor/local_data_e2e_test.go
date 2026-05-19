package doctor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/localloop"
)

func TestRunReportsLocalSQLiteData(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".intentproof", "local")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dataDir, "local.db")
	db, err := localloop.OpenDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := localloop.EnsureTenant(context.Background(), db, localloop.LocalTenantID); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	sdkDir := filepath.Join(home, ".intentproof", "sdk-node")
	if err := os.MkdirAll(sdkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	kp := map[string]string{"privateKey": "AAAA", "instanceId": "inst_test"}
	raw, _ := json.Marshal(kp)
	if err := os.WriteFile(filepath.Join(sdkDir, "keypair.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	report := Run(context.Background(), Options{HomeDir: home, Cwd: t.TempDir()})
	out := FormatReport(report)
	if !strings.Contains(out, "local database") {
		t.Fatalf("expected local database check, got:\n%s", out)
	}
}
