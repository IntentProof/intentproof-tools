package localloop

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/bundle"
)

func TestLocalVerifierHandlerVerifyRun(t *testing.T) {
	h := LocalVerifierHandler()
	body := []byte(`{"flow":{"events":[]},"policy":{"rules":[]},"attestations":""}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/run", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["status"] == nil {
		t.Fatalf("expected status in run: %#v", got)
	}
}

func TestLocalVerifierHandlerHealthz(t *testing.T) {
	h := LocalVerifierHandler()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("unexpected health: %d %q", rec.Code, rec.Body.String())
	}
}

func TestLocalVerifierHandlerVerifyBundle_unsignedPass(t *testing.T) {
	t.Setenv(EnvLocalBundleVerifyPubkey, "")
	h := LocalVerifierHandler()
	tarBody := mustTestProofTar(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/bundle", bytes.NewReader(tarBody))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var got bundle.VerifyResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "pass" {
		t.Fatalf("expected pass, got %#v", got)
	}
}

func TestLocalVerifierHandlerVerifyBundle_signedWithEnvPubkey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	t.Setenv(EnvLocalBundleVerifyPubkey, hex.EncodeToString(pub))

	h := LocalVerifierHandler()
	tarBody := mustTestProofTar(t, priv)
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/bundle", bytes.NewReader(tarBody))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var got bundle.VerifyResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "pass" {
		t.Fatalf("expected pass, got %#v", got)
	}
}

func TestLocalVerifierHandlerVerifyBundle_signedWrongEnvPubkey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongPub := wrongPriv.Public().(ed25519.PublicKey)
	t.Setenv(EnvLocalBundleVerifyPubkey, hex.EncodeToString(wrongPub))

	h := LocalVerifierHandler()
	tarBody := mustTestProofTar(t, priv)
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/bundle", bytes.NewReader(tarBody))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var got bundle.VerifyResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "fail" || got.Reason != "bundle.signature_invalid" {
		t.Fatalf("expected signature fail, got %#v", got)
	}
}

func TestLocalVerifierHandlerVerifyBundle_badPubkeyEnv(t *testing.T) {
	t.Setenv(EnvLocalBundleVerifyPubkey, "not-hex")
	h := LocalVerifierHandler()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/bundle", bytes.NewReader([]byte("x")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestLocalVerifierHandlerVerifyBundle_methodNotAllowed(t *testing.T) {
	t.Setenv(EnvLocalBundleVerifyPubkey, "")
	h := LocalVerifierHandler()
	req := httptest.NewRequest(http.MethodGet, "/v1/verify/bundle", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestLocalVerifierHandlerVerifyBundle_emptyBody(t *testing.T) {
	t.Setenv(EnvLocalBundleVerifyPubkey, "")
	h := LocalVerifierHandler()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/bundle", bytes.NewReader(nil))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}

func TestLocalPublicBaseURL(t *testing.T) {
	if u := LocalPublicBaseURL(":9787"); u != "http://localhost:9787" {
		t.Fatalf("got %q", u)
	}
	if u := LocalPublicBaseURL(""); u != "http://localhost:9787" {
		t.Fatalf("empty default got %q", u)
	}
}

func TestLocalDashboardHandler_healthzAndHome(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "dash.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	links := LocalDashboardLinks{
		IngestURL:    "http://localhost:19777",
		VerifierURL:  "http://localhost:19788",
		DashboardURL: "http://localhost:19799",
	}
	h := LocalDashboardHandler(db, links)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("healthz: %d %q", rec.Code, rec.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("home: %d", rec2.Code)
	}
	body := rec2.Body.String()
	if !strings.Contains(body, "Endpoints") {
		t.Fatalf("expected endpoints panel in HTML")
	}
	if !strings.Contains(body, "http://localhost:19777/v1/events") {
		t.Fatalf("expected ingest URL in HTML")
	}
	if !strings.Contains(body, "Flows") {
		t.Fatalf("expected flows section")
	}
}

func TestLocalDashboard_flowSortOpenBeforeClosed(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "sort.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`INSERT INTO flows (tenant_id, flow_id, correlation_id, window_closed_at, event_count, flow_merkle_root)
		VALUES (?, 'flow_closed', 'corr_closed', '2020-01-01T00:00:00Z', 1, 'sha256:aa')`, LocalTenantID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO flows (tenant_id, flow_id, correlation_id, window_opened_at, window_closed_at, event_count, flow_merkle_root)
		VALUES (?, 'flow_open', 'corr_open', '2026-01-01T00:00:00Z', NULL, 1, 'sha256:bb')`, LocalTenantID)
	if err != nil {
		t.Fatal(err)
	}
	h := LocalDashboardHandler(db, LocalDashboardLinks{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("home: %d", rec.Code)
	}
	body := rec.Body.String()
	iOpen := strings.Index(body, "corr_open")
	iClosed := strings.Index(body, "corr_closed")
	if iOpen < 0 || iClosed < 0 {
		t.Fatalf("missing correlations open=%d closed=%d", iOpen, iClosed)
	}
	if iOpen > iClosed {
		t.Fatalf("open flow should sort before closed: open idx=%d closed idx=%d", iOpen, iClosed)
	}
}

func mustTestProofTar(t *testing.T, signerPriv ed25519.PrivateKey) []byte {
	t.Helper()
	flowJSON, _ := json.Marshal(map[string]interface{}{
		"flow_id":   "f1",
		"tenant_id": "tnt",
		"events":    []string{"e1", "e2"},
	})
	eventsJSONL := []byte(`{"event_id":"e1","action":"pay","status":"ok"}` + "\n" +
		`{"event_id":"e2","action":"refund","status":"ok"}`)
	attsJSONL := []byte(`{"attestation_id":"a1","claim":"refund.ok","claim_value":true}`)
	policyJSON, _ := json.Marshal(map[string]interface{}{
		"policy_id": "p1",
		"rules":     []interface{}{},
	})
	runJSON, _ := json.Marshal(map[string]interface{}{
		"run_id":   "run_f1",
		"flow_id":  "f1",
		"status":   "pass",
		"findings": []interface{}{},
	})

	opts := bundle.CreateOptions{
		BundleID:          "bundle_f1",
		FlowID:            "f1",
		TenantID:          "tnt",
		FlowJSON:          flowJSON,
		EventsJSONL:       eventsJSONL,
		AttestationsJSONL: attsJSONL,
		PolicyJSON:        policyJSON,
		RunJSON:           runJSON,
	}
	if signerPriv != nil {
		opts.Signer = func(data []byte) (*bundle.SignatureEnvelope, error) {
			sum := sha256.Sum256(data)
			sig := ed25519.Sign(signerPriv, sum[:])
			return &bundle.SignatureEnvelope{
				Alg:   "ed25519",
				KeyID: "test",
				Value: hex.EncodeToString(sig),
			}, nil
		}
	}
	var buf bytes.Buffer
	if err := bundle.Create(&buf, opts); err != nil {
		t.Fatalf("bundle.Create: %v", err)
	}
	return buf.Bytes()
}
