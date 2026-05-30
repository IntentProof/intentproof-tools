package demo

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/localloop"
)

func TestStripeGoldenFixtureVerifyAndCanonicalize(t *testing.T) {
	root := goldenStripeRoot(t)
	body := mustReadStripe(t, filepath.Join(root, "refund-created.bytes"))
	shaPath := filepath.Join(root, "refund-created.sha256.txt")
	wantSHA := strings.TrimSpace(string(mustReadStripe(t, shaPath)))
	gotSHA := sha256.Sum256(body)
	if hex.EncodeToString(gotSHA[:]) != wantSHA {
		t.Fatalf("fixture body sha256 mismatch")
	}

	var headers map[string]string
	if err := json.Unmarshal(mustReadStripe(t, filepath.Join(root, "refund-created.headers.json")), &headers); err != nil {
		t.Fatalf("decode headers: %v", err)
	}
	ts, err := stripeSignatureTimestamp(headers)
	if err != nil {
		t.Fatal(err)
	}
	ctx := stripeWithVerifyClock(context.Background(), time.Unix(ts, 0).UTC())

	var adapter stripeWebhookAdapter
	if err := adapter.Verify(ctx, stripeDemoHMACSecret, headers, body); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	res, err := adapter.Canonicalize(ctx, body)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if res.SubjectType != "stripe_refund" || res.SubjectID != "re_demo_golden_001" {
		t.Fatalf("unexpected canonical result: %+v", res)
	}
}

func TestReplayStripeDemoIntoStore(t *testing.T) {
	scenario, err := LoadRefundScenario()
	if err != nil {
		t.Fatal(err)
	}
	store := newAttestMemoryStore()
	priv := ed25519.NewKeyFromSeed(deterministicRefundSeed())
	fixed := time.Date(2026, 5, 15, 12, 5, 0, 0, time.UTC)
	if err := replayStripeDemoAttestationIntoStore(store, localloop.LocalTenantID, priv, scenario, fixed); err != nil {
		t.Fatal(err)
	}
	if len(store.attestationsJSONL()) == 0 {
		t.Fatal("expected attestation bytes")
	}
}

func goldenStripeRoot(t *testing.T) string {
	t.Helper()
	root, err := GoldenDemoRoot()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "stripe")
}

func mustReadStripe(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStripeReplayDuplicate(t *testing.T) {
	scenario, err := LoadRefundScenario()
	if err != nil {
		t.Fatal(err)
	}
	store := newAttestMemoryStore()
	priv := ed25519.NewKeyFromSeed(deterministicRefundSeed())
	fixed := time.Date(2026, 5, 15, 12, 5, 0, 0, time.UTC)
	if err := replayStripeDemoAttestationIntoStore(store, localloop.LocalTenantID, priv, scenario, fixed); err != nil {
		t.Fatal(err)
	}
	if err := replayStripeDemoAttestationIntoStore(store, localloop.LocalTenantID, priv, scenario, fixed); err != nil {
		t.Fatal(err)
	}
	if len(store.records) != 1 {
		t.Fatalf("records=%d", len(store.records))
	}
}

func TestSpecRootFromEnvAbsolute(t *testing.T) {
	abs := absoluteSpecDirWithGoldenDemo(t)
	root, err := specRootFromEnv(abs)
	if err != nil {
		t.Fatal(err)
	}
	if root != abs {
		t.Fatalf("root=%q abs=%q", root, abs)
	}
}

func TestGoldenDemoRootFromEnvFunction(t *testing.T) {
	abs := absoluteSpecDirWithGoldenDemo(t)
	root, err := goldenDemoRootFromEnv(abs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(root, "golden/demo") {
		t.Fatalf("root=%q", root)
	}
}

func absoluteSpecDirWithGoldenDemo(t *testing.T) string {
	t.Helper()
	modRoot, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{
		filepath.Join(modRoot, "intentproof-spec"),
		filepath.Join(modRoot, "..", "intentproof-spec"),
	} {
		abs, err := filepath.Abs(candidate)
		if err != nil {
			t.Fatal(err)
		}
		demoRoot := filepath.Join(abs, "golden", "demo")
		if st, err := os.Stat(demoRoot); err == nil && st.IsDir() {
			return abs
		}
	}
	t.Skip("intentproof-spec/golden/demo not found for absolute env test")
	return ""
}

func TestSpecRootMonorepoFallback(t *testing.T) {
	t.Setenv("INTENTPROOF_SPEC_DIR", "")
	root, err := GoldenDemoRoot()
	if err != nil {
		t.Skip(err)
	}
	if root == "" {
		t.Fatal("expected root")
	}
}

func TestStripeVerifyClockSkew(t *testing.T) {
	var adapter stripeWebhookAdapter
	body := []byte(`{"id":"evt","type":"refund.updated","created":1,"data":{"object":{"id":"re"}}}`)
	headers := map[string]string{"stripe-signature": "t=1,v1=abc"}
	ctx := stripeWithVerifyClock(context.Background(), time.Unix(9999999999, 0))
	if err := adapter.Verify(ctx, "secret", headers, body); err == nil {
		t.Fatal("expected clock skew error")
	}
}

func TestParseStripeSignatureErrors(t *testing.T) {
	if _, _, err := parseStripeSignature("bad"); err == nil {
		t.Fatal("expected parse error")
	}
	if _, _, err := parseStripeSignature("t=notint,v1=abc"); err == nil {
		t.Fatal("expected timestamp parse error")
	}
}

func TestExtractRefundObjectErrors(t *testing.T) {
	if _, err := extractRefundObject("charge.refunded", map[string]any{"refunds": map[string]any{"data": []any{1}}}); err == nil {
		t.Fatal("expected invalid refund object")
	}
	if _, err := extractRefundObject("invoice.paid", map[string]any{}); err == nil {
		t.Fatal("expected unsupported event")
	}
}

func TestStripeReplayKeyAndSignature(t *testing.T) {
	var adapter stripeWebhookAdapter
	body := []byte(`{"id":"evt_1","type":"refund.updated"}`)
	headers := map[string]string{"stripe-signature": "t=1,v1=abc"}
	if adapter.ReplayKey(context.Background(), headers, body) != "evt_1" {
		t.Fatal("expected event id replay key")
	}
	if adapter.ReplayKey(context.Background(), headers, []byte("not-json")) == "" {
		t.Fatal("expected hash replay key fallback")
	}
	sig := adapter.SourceSignature(headers)
	if sig["alg"] != "hmac-sha256" {
		t.Fatalf("sig=%v", sig)
	}
}

func TestStripeExtractRefundObjectChargeRefunded(t *testing.T) {
	obj := map[string]any{
		"refunds": map[string]any{
			"data": []any{map[string]any{"id": "re_1", "amount": 100}},
		},
	}
	got, err := extractRefundObject("charge.refunded", obj)
	if err != nil || got["id"] != "re_1" {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestStripeCanonicalizeErrors(t *testing.T) {
	var adapter stripeWebhookAdapter
	if _, err := adapter.Canonicalize(context.Background(), []byte("{")); err == nil {
		t.Fatal("expected json error")
	}
}

func TestStripeVerifyRejectsBadSignature(t *testing.T) {
	var adapter stripeWebhookAdapter
	err := adapter.Verify(context.Background(), "secret", map[string]string{
		"stripe-signature": "t=1704067200,v1=deadbeef",
	}, []byte(`{"id":"evt"}`))
	if err == nil {
		t.Fatal("expected verify failure")
	}
}
