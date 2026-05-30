package demo

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSpecSemanticsPathMissingCatalog(t *testing.T) {
	root := t.TempDir()
	demoRoot := filepath.Join(root, "golden", "demo")
	if err := os.MkdirAll(demoRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_SPEC_DIR", root)
	if _, err := SpecSemanticsPath(); err == nil {
		t.Fatal("expected missing catalog error")
	}
}

func TestExpectedBundleHashPathMissing(t *testing.T) {
	root := t.TempDir()
	demoRoot := filepath.Join(root, "golden", "demo")
	if err := os.MkdirAll(demoRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_SPEC_DIR", root)
	if _, err := ExpectedBundleHashPath(); err == nil {
		t.Fatal("expected missing hash file error")
	}
}

func TestLoadRefundScenarioBadHeadersJSON(t *testing.T) {
	root := t.TempDir()
	demoRoot := filepath.Join(root, "golden", "demo")
	scenarios := filepath.Join(demoRoot, "scenarios")
	policyDir := filepath.Join(demoRoot, "policies")
	stripeDir := filepath.Join(demoRoot, "stripe")
	for _, dir := range []string{scenarios, policyDir, stripeDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(scenarios, "refund.json"), []byte(`{
  "happy_path":{"correlation_id":"a","actions":["x"]},
  "divergent_path":{"correlation_id":"b","actions":["x"]}
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "refund-with-notification.yaml"), []byte("rules: []"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stripeDir, "refund-created.bytes"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stripeDir, "refund-created.headers.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_SPEC_DIR", root)
	if _, err := LoadRefundScenario(); err == nil {
		t.Fatal("expected headers decode error")
	}
}

func TestLoadReasonCopyTitleFallback(t *testing.T) {
	root := t.TempDir()
	demoRoot := filepath.Join(root, "golden", "demo")
	semantics := filepath.Join(root, "semantics")
	for _, dir := range []string{demoRoot, semantics} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	catalog := map[string]any{
		"version": "1",
		"reasons": []map[string]any{{
			"code":        "demo.empty.title",
			"description": "Description becomes title",
			"title":       "",
		}},
	}
	raw, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(semantics, "reasons.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_SPEC_DIR", root)
	copy, err := LoadReasonCopy("demo.empty.title")
	if err != nil {
		t.Fatal(err)
	}
	if copy.Title != "Description becomes title" {
		t.Fatalf("title=%q", copy.Title)
	}
}

func TestFormatFindingCopyFull(t *testing.T) {
	out := FormatFindingCopy(ReasonCopy{
		Code:             "fail.required.missing",
		Title:            "Missing step",
		Description:      "A required action did not run",
		TypicalCauses:    []string{"Worker crash", "Misconfigured queue"},
		DocumentationURL: "https://example.com/docs",
	})
	for _, want := range []string{"Why it matters", "Worker crash", "https://example.com/docs"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
}

func TestStripeVerifyMissingSignatureHeader(t *testing.T) {
	var adapter stripeWebhookAdapter
	if err := adapter.Verify(context.Background(), "secret", map[string]string{}, []byte(`{}`)); err == nil {
		t.Fatal("expected missing signature error")
	}
}

func TestStripeSignatureTimestampMissing(t *testing.T) {
	if _, err := stripeSignatureTimestamp(map[string]string{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseStripeSignatureMissingFields(t *testing.T) {
	if _, _, err := parseStripeSignature("t=1704067200"); err == nil {
		t.Fatal("expected missing v1 error")
	}
}

func TestStripeCanonicalizeChargeRefunded(t *testing.T) {
	var adapter stripeWebhookAdapter
	body := []byte(`{
  "id":"evt_charge","type":"charge.refunded","created":1704067200,
  "data":{"object":{"refunds":{"data":[{"id":"re_charge","amount":500}]}}}
}`)
	res, err := adapter.Canonicalize(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	if res.SubjectID != "re_charge" {
		t.Fatalf("subject=%q", res.SubjectID)
	}
}

func TestStripeCanonicalizeMissingFields(t *testing.T) {
	var adapter stripeWebhookAdapter
	if _, err := adapter.Canonicalize(context.Background(), []byte(`{"id":"","type":"refund.updated","created":0,"data":{"object":{}}}`)); err == nil {
		t.Fatal("expected missing fields error")
	}
}

func TestExtractRefundObjectMissingRefunds(t *testing.T) {
	if _, err := extractRefundObject("charge.refunded", map[string]any{}); err == nil {
		t.Fatal("expected missing refunds error")
	}
	if _, err := extractRefundObject("charge.refunded", map[string]any{
		"refunds": map[string]any{"data": []any{}},
	}); err == nil {
		t.Fatal("expected missing data error")
	}
}

func TestExtractRefundObjectRefundPrefix(t *testing.T) {
	obj := map[string]any{"id": "re_direct"}
	got, err := extractRefundObject("refund.created", obj)
	if err != nil || got["id"] != "re_direct" {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestAttestationsJSONLMultiRecord(t *testing.T) {
	store := newAttestMemoryStore()
	store.records = []attestRecord{
		{body: []byte(`{"a":1}`)},
		{body: []byte(`{"b":2}`)},
	}
	got := string(store.attestationsJSONL())
	if !strings.Contains(got, "\n") || !strings.Contains(got, `{"a":1}`) {
		t.Fatalf("got=%q", got)
	}
}

func TestReplayStripeDemoVerifyFailure(t *testing.T) {
	scenario := RefundScenario{
		StripeBody:    []byte(`{"id":"evt","type":"refund.updated","created":1,"data":{"object":{"id":"re"}}}`),
		StripeHeaders: map[string]string{"stripe-signature": "t=1704067200,v1=deadbeef"},
	}
	store := newAttestMemoryStore()
	priv := ed25519.NewKeyFromSeed(deterministicRefundSeed())
	err := replayStripeDemoAttestationIntoStore(store, "tenant", priv, scenario, time.Now())
	if err == nil || !strings.Contains(err.Error(), "verify") {
		t.Fatalf("err=%v", err)
	}
}

func TestReplayStripeDemoBadHeaders(t *testing.T) {
	scenario := RefundScenario{
		StripeBody:    []byte(`{}`),
		StripeHeaders: map[string]string{},
	}
	store := newAttestMemoryStore()
	priv := ed25519.NewKeyFromSeed(deterministicRefundSeed())
	err := replayStripeDemoAttestationIntoStore(store, "tenant", priv, scenario, time.Now())
	if err == nil || !strings.Contains(err.Error(), "headers") {
		t.Fatalf("err=%v", err)
	}
}

func TestReplayStripeDemoCanonicalizeFailure(t *testing.T) {
	ts := int64(1704067200)
	body := []byte(`{"id":"evt","type":"invoice.paid","created":123,"data":{"object":{}}}`)
	scenario := RefundScenario{
		StripeBody: body,
		StripeHeaders: map[string]string{
			"stripe-signature": demoStripeSignature(ts, body),
		},
	}
	store := newAttestMemoryStore()
	priv := ed25519.NewKeyFromSeed(deterministicRefundSeed())
	err := replayStripeDemoAttestationIntoStore(store, "tenant", priv, scenario, time.Unix(ts, 0))
	if err == nil || !strings.Contains(err.Error(), "canonicalize") {
		t.Fatalf("err=%v", err)
	}
}

func demoStripeSignature(ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(stripeDemoHMACSecret))
	_, _ = mac.Write([]byte(strconv.FormatInt(ts, 10) + "." + string(body)))
	return "t=" + strconv.FormatInt(ts, 10) + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func TestStripeVerifySuccess(t *testing.T) {
	ts := int64(1704067200)
	body := []byte(`{"id":"evt","type":"refund.updated","created":123,"data":{"object":{"id":"re"}}}`)
	headers := map[string]string{"stripe-signature": demoStripeSignature(ts, body)}
	var adapter stripeWebhookAdapter
	ctx := stripeWithVerifyClock(context.Background(), time.Unix(ts, 0).UTC())
	if err := adapter.Verify(ctx, stripeDemoHMACSecret, headers, body); err != nil {
		t.Fatal(err)
	}
}

func TestGoldenDemoRootMissingUnderSpec(t *testing.T) {
	root := t.TempDir()
	t.Setenv("INTENTPROOF_SPEC_DIR", root)
	if _, err := goldenDemoRootFromEnv(root); err == nil {
		t.Fatal("expected error when spec root lacks golden/demo")
	}
}

func TestSpecRootFromEnvInvalidRelative(t *testing.T) {
	t.Setenv("INTENTPROOF_SPEC_DIR", "no-such-spec-dir")
	if _, err := specRootFromEnv("no-such-spec-dir"); err == nil {
		t.Fatal("expected error for invalid relative spec dir")
	}
}

func TestSpecRootFromEnvRelativeSibling(t *testing.T) {
	sibling := filepath.Join("..", "intentproof-spec")
	if _, err := os.Stat(filepath.Join(sibling, "golden", "demo")); err != nil {
		t.Skip("sibling spec missing")
	}
	if _, err := specRootFromEnv(sibling); err != nil {
		t.Fatal(err)
	}
}

func TestIndentJSON(t *testing.T) {
	got, err := indentJSON([]byte(`{"a":1}`))
	if err != nil || !strings.Contains(string(got), "\n") {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if _, err := indentJSON([]byte(`{`)); err == nil {
		t.Fatal("expected indent error")
	}
}

func TestDemoIntentForActionDefault(t *testing.T) {
	if got := demoIntentForAction("custom.action"); got != "custom.action" {
		t.Fatalf("got=%q", got)
	}
	for action, want := range map[string]string{
		"payments.refund.execute": "Execute customer refund",
		"ledger.entry.write":      "Record ledger reversal",
		"customer.notify":         "Notify customer of refund",
	} {
		if got := demoIntentForAction(action); got != want {
			t.Fatalf("%s: got=%q want=%q", action, got, want)
		}
	}
}

func TestLoadRefundScenarioMissingScenarioFile(t *testing.T) {
	root := t.TempDir()
	demoRoot := filepath.Join(root, "golden", "demo")
	if err := os.MkdirAll(filepath.Join(demoRoot, "scenarios"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_SPEC_DIR", root)
	if _, err := LoadRefundScenario(); err == nil {
		t.Fatal("expected read scenario error")
	}
}

func TestStripeCanonicalizeUnsupportedEventType(t *testing.T) {
	var adapter stripeWebhookAdapter
	body := []byte(`{"id":"evt","type":"invoice.paid","created":123,"data":{"object":{}}}`)
	if _, err := adapter.Canonicalize(context.Background(), body); err == nil {
		t.Fatal("expected unsupported event type error")
	}
}

func TestStripeCanonicalizeUsesEventIDWithoutRefundID(t *testing.T) {
	var adapter stripeWebhookAdapter
	body := []byte(`{"id":"evt_only","type":"refund.updated","created":123,"data":{"object":{"amount":100}}}`)
	res, err := adapter.Canonicalize(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	if res.SubjectID != "evt_only" {
		t.Fatalf("subject=%q", res.SubjectID)
	}
}

func TestLoadRefundScenarioGoldenRootMissing(t *testing.T) {
	t.Setenv("INTENTPROOF_SPEC_DIR", t.TempDir())
	if _, err := LoadRefundScenario(); err == nil {
		t.Fatal("expected golden root error")
	}
}

func TestExpectedBundleHashPathGoldenRootMissing(t *testing.T) {
	t.Setenv("INTENTPROOF_SPEC_DIR", t.TempDir())
	if _, err := ExpectedBundleHashPath(); err == nil {
		t.Fatal("expected golden root error")
	}
}

func TestLoadReasonCopyMissingSemanticsFile(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "golden", "demo"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_SPEC_DIR", root)
	if _, err := LoadReasonCopy("fail.required.missing"); err == nil {
		t.Fatal("expected missing semantics error")
	}
}

func TestLoadReasonCopyReadFailure(t *testing.T) {
	root := t.TempDir()
	demoRoot := filepath.Join(root, "golden", "demo")
	semantics := filepath.Join(root, "semantics")
	for _, dir := range []string{demoRoot, semantics} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	catalogPath := filepath.Join(semantics, "reasons.json")
	if err := os.Mkdir(catalogPath, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_SPEC_DIR", root)
	if _, err := LoadReasonCopy("fail.required.missing"); err == nil {
		t.Fatal("expected read error")
	}
}
