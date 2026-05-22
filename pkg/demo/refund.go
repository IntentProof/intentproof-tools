package demo

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/bundle"
	"github.com/intentproof/intentproof-tools/pkg/localloop"
	"github.com/intentproof/intentproof-tools/pkg/policy"
	"github.com/intentproof/intentproof-tools/pkg/verifier"
)

//go:embed refund_policy.yaml
var refundPolicyYAML []byte

const (
	corrRefundOK             = "corr_demo_refund_ok"
	corrRefundMissingNotify  = "corr_demo_refund_missing_notify"
	chainAnchorPrevEventHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

// refundListenTCP and refundNewHTTPClient are overridden in tests to exercise
// RunRefund error paths without changing production defaults.
var (
	refundListenTCP         = net.Listen
	refundNewHTTPClient     = func() *http.Client { return &http.Client{Timeout: 10 * time.Second} }
	refundCompilePolicy     = policy.Compile
	refundBuildFlowJSON     = localloop.BuildVerifierFlowJSON
	refundVerifyFlow        = verifier.Verify
	refundLoadEventsJSONL   = localloop.LoadEventsJSONL
	refundLoadSDKPublicKeys = localloop.LoadSDKPublicKeysForCorrelation
	refundBundleCreate      = bundle.Create
	refundRegisterSDK       = localloop.RegisterSDKInstance
	refundStartNATS         = localloop.StartEmbeddedNATS
	refundGenerateKey       = ed25519.GenerateKey
	refundUserHomeDir       = os.UserHomeDir
	refundJSONMarshal       = json.Marshal
	refundJSONMarshalIndent = json.MarshalIndent
	refundIndentJSON        = indentJSON
)

// Options configures the refund demo.
type Options struct {
	Stdout io.Writer
	Stderr io.Writer
	// HomeDir is the synthetic HOME layout root (.intentproof/local lives here).
	HomeDir string
	// WorkDir is where demo-refund.proof.tar.zst is written.
	WorkDir     string
	OpenBrowser bool
	// PrivateKeySeed and FixedTime make the demo reproducible for golden tests.
	PrivateKeySeed []byte
	FixedTime      time.Time
}

// RunRefund runs the refund demo: local ingest + flow builder, happy and
// divergent event chains, policy evaluation, and bundle export.
func RunRefund(ctx context.Context, opt Options) error {
	if opt.Stdout == nil {
		opt.Stdout = os.Stdout
	}
	if opt.Stderr == nil {
		opt.Stderr = os.Stderr
	}
	if opt.HomeDir == "" {
		h, err := refundUserHomeDir()
		if err != nil {
			return fmt.Errorf("home dir: %w", err)
		}
		opt.HomeDir = h
	}
	if opt.WorkDir == "" {
		opt.WorkDir = "."
	}

	dataDir := filepath.Join(opt.HomeDir, ".intentproof", "local")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	dbPath := filepath.Join(dataDir, "local.db")
	db, err := localloop.OpenDB(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	var priv ed25519.PrivateKey
	if len(opt.PrivateKeySeed) > 0 {
		if len(opt.PrivateKeySeed) != ed25519.SeedSize {
			return fmt.Errorf("private key seed: want %d bytes, got %d", ed25519.SeedSize, len(opt.PrivateKeySeed))
		}
		priv = ed25519.NewKeyFromSeed(opt.PrivateKeySeed)
	} else {
		_, generated, err := refundGenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}
		priv = generated
	}
	instanceID := "inst_demo_refund"
	regCtx := context.Background()
	if err := refundRegisterSDK(regCtx, db, localloop.LocalTenantID, instanceID, priv.Public().(ed25519.PublicKey)); err != nil {
		return fmt.Errorf("register sdk: %w", err)
	}

	natsDir := filepath.Join(dataDir, "nats-demo")
	nats, err := refundStartNATS(natsDir)
	if err != nil {
		return fmt.Errorf("start nats: %w", err)
	}
	defer nats.Shutdown()

	flowCtx, stopFlow := context.WithCancel(context.Background())
	defer stopFlow()
	go func() { _ = localloop.NewFlowBuilder(db, nats).Run(flowCtx) }()

	ingestL, err := refundListenTCP("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen ingest: %w", err)
	}
	verL, err := refundListenTCP("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen verifier: %w", err)
	}
	dashL, err := refundListenTCP("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen dashboard: %w", err)
	}

	ingestURL := "http://" + ingestL.Addr().String()
	verifierURL := "http://" + verL.Addr().String()
	dashboardURL := "http://" + dashL.Addr().String()

	dashLinks := localloop.LocalDashboardLinks{
		IngestURL:    ingestURL,
		VerifierURL:  verifierURL,
		DashboardURL: dashboardURL,
	}

	ingestSrv := localloop.NewIngestServer(ingestL.Addr().String(), db, nats)
	ingestHTTPSrv := &http.Server{Handler: ingestSrv.Handler()}
	verHTTPSrv := &http.Server{Handler: localloop.LocalVerifierHandler()}
	dashHTTPSrv := &http.Server{Handler: localloop.LocalDashboardHandler(db, dashLinks)}

	go func() {
		if err := ingestHTTPSrv.Serve(ingestL); err != nil && err != http.ErrServerClosed {
			_, _ = fmt.Fprintf(opt.Stderr, "ingest server exited: %v\n", err)
		}
	}()
	go func() {
		if err := verHTTPSrv.Serve(verL); err != nil && err != http.ErrServerClosed {
			_, _ = fmt.Fprintf(opt.Stderr, "verifier server exited: %v\n", err)
		}
	}()
	go func() {
		if err := dashHTTPSrv.Serve(dashL); err != nil && err != http.ErrServerClosed {
			_, _ = fmt.Fprintf(opt.Stderr, "dashboard server exited: %v\n", err)
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = ingestHTTPSrv.Shutdown(shutdownCtx)
		_ = verHTTPSrv.Shutdown(shutdownCtx)
		_ = dashHTTPSrv.Shutdown(shutdownCtx)
	}()

	client := refundNewHTTPClient()
	if err := waitHTTP(ctx, client, []string{
		ingestURL + "/healthz",
		verifierURL + "/healthz",
		dashboardURL + "/healthz",
	}); err != nil {
		return err
	}

	baseTime := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	if err := postActionChain(client, ingestURL+"/v1/events", priv, instanceID, corrRefundOK, []string{
		"payments.refund.execute",
		"ledger.entry.write",
		"customer.notify",
	}, baseTime); err != nil {
		return fmt.Errorf("post happy path: %w", err)
	}
	if err := postActionChain(client, ingestURL+"/v1/events", priv, instanceID, corrRefundMissingNotify, []string{
		"payments.refund.execute",
		"ledger.entry.write",
	}, baseTime.Add(2*time.Minute)); err != nil {
		return fmt.Errorf("post divergent path: %w", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := waitForCorrelationFlow(waitCtx, db, corrRefundOK, 3); err != nil {
		return err
	}
	if err := waitForCorrelationFlow(waitCtx, db, corrRefundMissingNotify, 2); err != nil {
		return err
	}

	compiled, err := refundCompilePolicy(refundPolicyYAML)
	if err != nil {
		return fmt.Errorf("compile policy: %w", err)
	}
	policyJSON, err := refundJSONMarshal(compiled.Policy)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}

	flowJSON, err := refundBuildFlowJSON(regCtx, db, localloop.LocalTenantID, corrRefundMissingNotify)
	if err != nil {
		return fmt.Errorf("build flow json: %w", err)
	}

	restoreClock := func() {}
	if !opt.FixedTime.IsZero() {
		fixed := opt.FixedTime.UTC()
		restoreClock = verifier.SetNowFuncForTest(func() time.Time { return fixed })
	}
	defer restoreClock()

	vrun, err := refundVerifyFlow(flowJSON, policyJSON, nil)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if vrun.Status != "fail" {
		return fmt.Errorf("expected verification status fail on divergent path, got %s", vrun.Status)
	}
	if !hasReason(vrun, "fail.required.missing") {
		return fmt.Errorf("expected finding reason fail.required.missing, got %+v", vrun.Findings)
	}

	okFlowJSON, err := refundBuildFlowJSON(regCtx, db, localloop.LocalTenantID, corrRefundOK)
	if err != nil {
		return fmt.Errorf("build ok flow json: %w", err)
	}
	okRun, err := refundVerifyFlow(okFlowJSON, policyJSON, nil)
	if err != nil {
		return fmt.Errorf("verify ok path: %w", err)
	}
	if okRun.Status != "pass" {
		return fmt.Errorf("expected verification pass on happy path, got %s", okRun.Status)
	}

	runJSON, err := refundJSONMarshalIndent(vrun, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal run: %w", err)
	}

	eventsJSONL, err := refundLoadEventsJSONL(regCtx, db, localloop.LocalTenantID, corrRefundMissingNotify)
	if err != nil {
		return fmt.Errorf("load events jsonl: %w", err)
	}
	publicKeys, err := refundLoadSDKPublicKeys(regCtx, db, localloop.LocalTenantID, corrRefundMissingNotify)
	if err != nil {
		return fmt.Errorf("load sdk public keys: %w", err)
	}

	flowPretty, err := refundIndentJSON(flowJSON)
	if err != nil {
		return fmt.Errorf("flow indent: %w", err)
	}
	policyPretty, err := refundIndentJSON(policyJSON)
	if err != nil {
		return fmt.Errorf("policy indent: %w", err)
	}

	bundlePath := filepath.Join(opt.WorkDir, "demo-refund.proof.tar.zst")
	bf, err := os.Create(bundlePath)
	if err != nil {
		return fmt.Errorf("create bundle: %w", err)
	}
	err = refundBundleCreate(bf, bundle.CreateOptions{
		BundleID:          "bnd_demo_refund",
		FlowID:            vrun.FlowID,
		TenantID:          localloop.LocalTenantID,
		FlowJSON:          flowPretty,
		EventsJSONL:       eventsJSONL,
		AttestationsJSONL: nil,
		PolicyJSON:        policyPretty,
		RunJSON:           runJSON,
		PublicKeys:        publicKeys,
		CreatedAt:         opt.FixedTime,
	})
	_ = bf.Close()
	if err != nil {
		return fmt.Errorf("bundle create: %w", err)
	}

	absBundle, err := filepath.Abs(bundlePath)
	if err != nil {
		absBundle = bundlePath
	}

	fmt.Fprintf(opt.Stdout, "Demo refund scenario finished.\n")
	fmt.Fprintf(opt.Stdout, "- Happy-path correlation: %s (policy passes).\n", corrRefundOK)
	fmt.Fprintf(opt.Stdout, "- Divergent correlation: %s (missing customer.notify).\n", corrRefundMissingNotify)
	fmt.Fprintf(opt.Stdout, "- Exported bundle: %s\n", absBundle)
	fmt.Fprintf(opt.Stdout, "  Re-verify: intentproof verify %s\n", absBundle)
	fmt.Fprintf(opt.Stdout, "  Dashboard: %s/\n", dashboardURL)

	if opt.OpenBrowser {
		attempted, err := localloop.OpenLocalDashboardBrowser(dashboardURL)
		if err != nil {
			fmt.Fprintf(opt.Stderr, "open dashboard: %v\n", err)
		} else if attempted {
			// Ephemeral servers stop as soon as this function returns; give the
			// browser time to load the dashboard before teardown.
			time.Sleep(900 * time.Millisecond)
		}
	}
	return nil
}

func waitHTTP(ctx context.Context, client *http.Client, urls []string) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		ok := true
		for _, u := range urls {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err != nil || resp.StatusCode != http.StatusOK {
				ok = false
				if resp != nil {
					_ = resp.Body.Close()
				}
				break
			}
			_ = resp.Body.Close()
		}
		if ok {
			return nil
		}
		time.Sleep(80 * time.Millisecond)
	}
	return fmt.Errorf("HTTP endpoints not ready within timeout")
}

func postActionChain(client *http.Client, ingestEvents string, priv ed25519.PrivateKey, instanceID, correlationID string, actions []string, t0 time.Time) error {
	prev := chainAnchorPrevEventHash
	for i, action := range actions {
		ev := localloop.ExecutionEvent{
			Schema:        "intentproof.event.v1",
			EventID:       fmt.Sprintf("evt_%s_%d", correlationID, i+1),
			TenantID:      localloop.LocalTenantID,
			InstanceID:    instanceID,
			CorrelationID: correlationID,
			PrevEventHash: prev,
			ChainPosition: i + 1,
			Intent:        demoIntentForAction(action),
			Action:        action,
			Status:        "ok",
			StartedAt:     t0.Add(time.Duration(i) * time.Second),
			CompletedAt:   t0.Add(time.Duration(i+1) * time.Second),
			DurationMS:    1000,
			Inputs:        []any{},
			Output:        map[string]any{"demo": true},
			SpecVersion:   "v1",
			SDKVersion:    "demo",
			Attributes:    map[string]any{},
		}
		signed, err := localloop.SignExecutionEvent(ev, priv)
		if err != nil {
			return fmt.Errorf("sign: %w", err)
		}
		body, err := json.Marshal(signed)
		if err != nil {
			return err
		}
		req, err := http.NewRequest(http.MethodPost, ingestEvents, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("post %s: %w", action, err)
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			return fmt.Errorf("post %s: status %d: %s", action, resp.StatusCode, string(data))
		}
		dig, err := localloop.EventChainDigest(signed)
		if err != nil {
			return err
		}
		prev = localloop.FormatChainHash(dig)
	}
	return nil
}

func demoIntentForAction(action string) string {
	switch action {
	case "payments.refund.execute":
		return "Execute customer refund"
	case "ledger.entry.write":
		return "Record ledger reversal"
	case "customer.notify":
		return "Notify customer of refund"
	default:
		return action
	}
}

func indentJSON(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func waitForCorrelationFlow(ctx context.Context, db *sql.DB, correlationID string, wantEvents int) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for flow %s with %d events: %w", correlationID, wantEvents, ctx.Err())
		default:
		}
		snap, err := localloop.GetFlowByCorrelationID(ctx, db, localloop.LocalTenantID, correlationID)
		if err == nil && len(snap.Events) >= wantEvents {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func hasReason(vrun *verifier.VerificationRun, code string) bool {
	for _, f := range vrun.Findings {
		if r, ok := f["reason"].(string); ok && r == code {
			return true
		}
	}
	return false
}
