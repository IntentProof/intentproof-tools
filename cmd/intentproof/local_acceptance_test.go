package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	instanceID := "inst_acceptance_1"
	sdkDir := filepath.Join(tmpDir, ".intentproof", "sdk-node")
	if err := os.MkdirAll(sdkDir, 0o700); err != nil {
		t.Fatalf("mkdir sdk dir: %v", err)
	}
	kp := map[string]string{
		"privateKey": base64.StdEncoding.EncodeToString(priv.Seed()),
		"instanceId": instanceID,
	}
	kpRaw, err := json.Marshal(kp)
	if err != nil {
		t.Fatalf("marshal keypair: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sdkDir, "keypair.json"), kpRaw, 0o600); err != nil {
		t.Fatalf("write keypair: %v", err)
	}

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
	ingestBase := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Timeout: 2 * time.Second}
	ready := false
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ingestBase+"/healthz", nil)
		if err != nil {
			t.Fatalf("build readiness request: %v", err)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
	}
	if !ready {
		t.Fatalf("ingest endpoint did not become ready within 10s")
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	event := localloop.ExecutionEvent{
		Schema:        "intentproof.event.v1",
		EventID:       "evt_01HZXTESTLOCAL01",
		TenantID:      localloop.LocalTenantID,
		InstanceID:    instanceID,
		CorrelationID: "corr_acceptance_1",
		PrevEventHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		ChainPosition: 1,
		Intent:        "test",
		Action:        "test.action",
		Status:        "ok",
		StartedAt:     now,
		CompletedAt:   now,
		DurationMS:    1,
		Inputs:        []any{},
		Output:        map[string]any{"ok": true},
		SpecVersion:   "v1",
		SDKVersion:    "test",
		Attributes:    map[string]any{},
	}
	event, err = localloop.SignExecutionEvent(event, priv)
	if err != nil {
		t.Fatalf("sign event: %v", err)
	}
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ingestBase+"/v1/events", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build post request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
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
