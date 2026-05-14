package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
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

	// Allocate a free port so the test doesn't flake when 9786 is taken.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "local")
	cmd.Env = append(os.Environ(), homeEnv, fmt.Sprintf("INTENTPROOF_LOCAL_INGEST_ADDR=:%d", port))
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
	ingestURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		resp, err := http.Get(ingestURL)
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

	resp, err := http.Post(ingestURL, "application/json", bytes.NewReader(body))
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
