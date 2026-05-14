package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/localloop"
)

// TestLocalAcceptance builds the CLI, starts `intentproof local`, posts an
// event, and verifies the flow is materialized within 5 seconds.
func TestLocalAcceptance(t *testing.T) {
	tmpDir := t.TempDir()
	homeEnv := "HOME=" + tmpDir

	bin := filepath.Join(tmpDir, "intentproof")
	build := exec.Command("go", "build", "-o", bin, "./cmd/intentproof")
	build.Dir = filepath.Join("..", "..")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build CLI: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "local")
	cmd.Env = append(os.Environ(), homeEnv)
	var stderrBuf bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		t.Fatalf("start CLI: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("CLI stderr:\n%s", stderrBuf.String())
		}
	}()

	// Wait for the ingest HTTP endpoint to come up (max 10s).
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		resp, err := http.Get("http://localhost:9786")
		if err == nil {
			_ = resp.Body.Close()
			break
		}
	}

	event := localloop.ExecutionEvent{
		Schema:        "intentproof.event.v1",
		EventID:       "evt_01HZXTESTLOCAL01",
		TenantID:      "tnt_local",
		InstanceID:    "inst_local_1",
		CorrelationID: "corr_acceptance_1",
		PrevEventHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		ChainPosition: 1,
		Intent:        "test",
		Action:        "test.action",
		Status:        "ok",
		StartedAt:     time.Now().UTC(),
		CompletedAt:   time.Now().UTC(),
		DurationMS:    1,
		SpecVersion:   "v1",
		SDKVersion:    "test",
		Signature: localloop.Signature{
			Alg:   "ed25519",
			KeyID: "local",
			Value: "dummysig",
		},
	}
	body, _ := json.Marshal(event)

	resp, err := http.Post("http://localhost:9786", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post event: %v", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	dbPath := filepath.Join(tmpDir, ".intentproof", "local", "local.db")
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if _, err := os.Stat(dbPath); err != nil {
			continue
		}
		db, err := localloop.OpenDB(dbPath)
		if err != nil {
			continue
		}
		flow, err := localloop.GetFlowByCorrelationID(context.Background(), db, "tnt_local", "corr_acceptance_1")
		_ = db.Close()
		if err == nil && flow != nil {
			return
		}
	}

	t.Fatal("flow was not materialized in SQLite within 5 seconds")
}
