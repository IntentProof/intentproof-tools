// local-seed posts signed sample execution events to a local (or any)
// intentproof ingest endpoint so materialized flows appear in the dashboard.
//
// Usage:
//
//	go run ./cmd/local-seed -n 5
//	go run ./cmd/local-seed -ingest http://127.0.0.1:9787/v1/events -keypair ~/.intentproof/sdk-node/keypair.json
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/localloop"
)

type sdkKeypairFile struct {
	PrivateKey string `json:"privateKey"`
	InstanceID string `json:"instanceId"`
}

func main() {
	ingest := flag.String("ingest", getenv("INTENTPROOF_INGEST_URL", "http://127.0.0.1:9787/v1/events"), "full ingest URL (POST /v1/events)")
	keypairPath := flag.String("keypair", "", "path to keypair.json (default: $HOME/.intentproof/sdk-node/keypair.json)")
	n := flag.Int("n", 5, "number of events, each with a distinct correlation_id (one flow each after materialization)")
	flag.Parse()

	kpPath := *keypairPath
	if kpPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "home dir: %v\n", err)
			os.Exit(1)
		}
		kpPath = filepath.Join(home, ".intentproof", "sdk-node", "keypair.json")
	}
	raw, err := os.ReadFile(kpPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read keypair %s: %v\n", kpPath, err)
		os.Exit(1)
	}
	var kp sdkKeypairFile
	if err := json.Unmarshal(raw, &kp); err != nil {
		fmt.Fprintf(os.Stderr, "parse keypair: %v\n", err)
		os.Exit(1)
	}
	seed, err := base64.StdEncoding.DecodeString(kp.PrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode privateKey: %v\n", err)
		os.Exit(1)
	}
	if len(seed) != ed25519.SeedSize {
		fmt.Fprintf(os.Stderr, "privateKey must decode to %d bytes (got %d)\n", ed25519.SeedSize, len(seed))
		os.Exit(1)
	}
	if kp.InstanceID == "" {
		fmt.Fprintf(os.Stderr, "keypair missing instanceId\n")
		os.Exit(1)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	client := &http.Client{Timeout: 10 * time.Second}
	base := time.Now().UTC().Truncate(time.Millisecond)

	for i := 0; i < *n; i++ {
		corr := fmt.Sprintf("corr_seed_%d_%d", base.UnixNano(), i)
		evID := fmt.Sprintf("evt_seed_%d_%d", base.UnixNano(), i)
		ev := localloop.ExecutionEvent{
			Schema:        "intentproof.event.v1",
			EventID:       evID,
			TenantID:      localloop.LocalTenantID,
			InstanceID:    kp.InstanceID,
			CorrelationID: corr,
			PrevEventHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			ChainPosition: 1,
			Intent:        "demo",
			Action:        "demo.seed",
			Status:        "ok",
			StartedAt:     base,
			CompletedAt:   base,
			DurationMS:    1,
			Inputs:        []any{},
			Output:        map[string]any{"sample_index": i},
			SpecVersion:   "v1",
			SDKVersion:    "local-seed",
			Attributes:    map[string]any{"source": "local-seed"},
		}
		ev, err = localloop.SignExecutionEvent(ev, priv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sign %s: %v\n", evID, err)
			os.Exit(1)
		}
		body, err := json.Marshal(ev)
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
			os.Exit(1)
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, *ingest, bytes.NewReader(body))
		if err != nil {
			fmt.Fprintf(os.Stderr, "request: %v\n", err)
			os.Exit(1)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "POST %s: %v\n", *ingest, err)
			os.Exit(1)
		}
		slurp, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			fmt.Fprintf(os.Stderr, "%s -> HTTP %d: %s\n", evID, resp.StatusCode, string(slurp))
			os.Exit(1)
		}
		fmt.Printf("accepted %s correlation=%s\n", evID, corr)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
