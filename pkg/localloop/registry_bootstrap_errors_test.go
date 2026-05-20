package localloop

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapLocalRegistryRejectsInvalidJSON(t *testing.T) {
	home := t.TempDir()
	sdkDir := filepath.Join(home, ".intentproof", "sdk-node")
	if err := os.MkdirAll(sdkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sdkDir, "keypair.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := OpenDB(filepath.Join(t.TempDir(), "boot_json.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = BootstrapLocalRegistry(context.Background(), db, home)
	if err == nil || !strings.Contains(err.Error(), "parse sdk keypair") {
		t.Fatalf("got %v", err)
	}
}

func TestBootstrapLocalRegistryRejectsMissingFields(t *testing.T) {
	home := t.TempDir()
	sdkDir := filepath.Join(home, ".intentproof", "sdk-node")
	if err := os.MkdirAll(sdkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sdkDir, "keypair.json"), []byte(`{"privateKey":"","instanceId":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := OpenDB(filepath.Join(t.TempDir(), "boot_fields.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = BootstrapLocalRegistry(context.Background(), db, home)
	if err == nil || !strings.Contains(err.Error(), "missing instanceId") {
		t.Fatalf("got %v", err)
	}
}

func TestBootstrapLocalRegistryRejectsInvalidSeedLength(t *testing.T) {
	home := t.TempDir()
	sdkDir := filepath.Join(home, ".intentproof", "sdk-node")
	if err := os.MkdirAll(sdkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Valid base64 but wrong byte length for ed25519 seed.
	if err := os.WriteFile(filepath.Join(sdkDir, "keypair.json"),
		[]byte(`{"privateKey":"AQID","instanceId":"inst_x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := OpenDB(filepath.Join(t.TempDir(), "boot_seed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = BootstrapLocalRegistry(context.Background(), db, home)
	if err == nil || !strings.Contains(err.Error(), "decode sdk private key") {
		t.Fatalf("got %v", err)
	}
}
