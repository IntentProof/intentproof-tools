package localloop

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/intentproof/intentproof-tools/pkg/bundle"
	"github.com/intentproof/intentproof-tools/pkg/verifier"
)

const maxVerifyRunBodyBytes = 8 << 20

// maxVerifyBundleBodyBytes caps the raw tar body for POST /v1/verify/bundle.
const maxVerifyBundleBodyBytes = 64 << 20

// EnvLocalBundleVerifyPubkey is optional hex-encoded Ed25519 public key (32
// bytes, 64 hex chars) used to verify the bundle manifest signature. When
// unset, manifest signature checks are skipped (integrity and Merkle checks
// still run when the bundle is signed or unsigned per bundle.Verify rules).
const EnvLocalBundleVerifyPubkey = "INTENTPROOF_LOCAL_BUNDLE_VERIFY_PUBKEY"

// localServicesJSONMarshal is overridden in tests for marshal failure paths.
var localServicesJSONMarshal = json.Marshal

// LocalVerifierHandler serves a minimal HTTP verifier API used by
// `intentproof local` on the verifier port (default :9788).
func LocalVerifierHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/v1/verify/run", handleVerifyRun)
	mux.HandleFunc("/v1/verify/bundle", handleVerifyBundle)
	return mux
}

type verifyRunRequest struct {
	Flow         json.RawMessage `json:"flow"`
	Policy       json.RawMessage `json:"policy"`
	Attestations string          `json:"attestations"`
}

func handleVerifyRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxVerifyRunBodyBytes))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var req verifyRunRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	if len(req.Flow) == 0 || len(req.Policy) == 0 {
		http.Error(w, `{"error":"flow_and_policy_required"}`, http.StatusBadRequest)
		return
	}
	vr, err := verifier.Verify(req.Flow, req.Policy, []byte(req.Attestations))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":  "verify_input",
			"detail": err.Error(),
		})
		return
	}
	out, err := localServicesJSONMarshal(vr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

func parseLocalBundleVerifyPubkey() ([]byte, error) {
	s := strings.TrimSpace(os.Getenv(EnvLocalBundleVerifyPubkey))
	if s == "" {
		return nil, nil
	}
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("want %d-byte ed25519 public key, got %d bytes",
			ed25519.PublicKeySize, len(decoded))
	}
	return decoded, nil
}

func handleVerifyBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	pubkey, err := parseLocalBundleVerifyPubkey()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":  "bundle_pubkey_config",
			"detail": err.Error(),
		})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxVerifyBundleBodyBytes))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":  "bundle_read_failed",
			"detail": err.Error(),
		})
		return
	}
	if len(body) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "empty_body"})
		return
	}
	vr, err := bundle.Verify(bytes.NewReader(body), pubkey)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":  "bundle_verify_error",
			"detail": err.Error(),
		})
		return
	}
	out, err := localServicesJSONMarshal(vr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}
