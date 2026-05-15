package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBootstrapLocalRegistryFromSDKKeypair(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	sdkDir := filepath.Join(home, ".intentproof", "sdk-node")
	if err := os.MkdirAll(sdkDir, 0o700); err != nil {
		t.Fatal(err)
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	instanceID := "inst_bootstrap"
	raw, _ := json.Marshal(map[string]string{
		"privateKey": base64.StdEncoding.EncodeToString(seed),
		"instanceId": instanceID,
	})
	if err := os.WriteFile(filepath.Join(sdkDir, "keypair.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	db, err := OpenDB(filepath.Join(dir, "local.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := BootstrapLocalRegistry(ctx, db, home); err != nil {
		t.Fatal(err)
	}

	ev := ExecutionEvent{
		Schema:        "intentproof.event.v1",
		EventID:       "evt_bootstrap",
		TenantID:      LocalTenantID,
		InstanceID:    instanceID,
		CorrelationID: "corr_bootstrap",
		PrevEventHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		ChainPosition: 1,
		Action:        "act",
		Status:        "ok",
		StartedAt:     mustTime(t),
		CompletedAt:   mustTime(t),
		DurationMS:    1,
		SpecVersion:   "1.0.0",
		Attributes:    map[string]any{},
	}
	ev, err = SignExecutionEvent(ev, priv)
	if err != nil {
		t.Fatal(err)
	}
	canonBytes, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256Sum(canonBytes)
	if err := verifyEventSignature(ctx, db, ev, d[:]); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func mustTime(t *testing.T) time.Time {
	t.Helper()
	return time.Now().UTC().Truncate(time.Millisecond)
}
