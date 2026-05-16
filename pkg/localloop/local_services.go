package localloop

import (
	"bytes"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
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
	out, err := json.Marshal(vr)
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
	out, err := json.Marshal(vr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// dashboardRow is one row in the local flows table view.
type dashboardRow struct {
	TenantID       string
	FlowID         string
	CorrelationID  string
	EventCount     int
	FlowMerkleRoot string
	WindowClosedAt string
	ClosureReason  string
	SnapshotURI    string
}

const dashboardPage = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>IntentProof local</title>
<style>
body{font-family:system-ui,sans-serif;margin:2rem;line-height:1.4}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ccc;padding:0.4rem 0.6rem;text-align:left;font-size:0.9rem}
th{background:#f4f4f4}
code{font-size:0.85rem}
.muted{color:#666;font-size:0.9rem}
</style>
</head>
<body>
<h1>IntentProof local</h1>
<p class="muted">Materialized flows for tenant <code>tnt_local</code> (most recent first).</p>
{{if .Err}}<p class="muted">Could not load flows: {{.Err}}</p>{{else if .Rows}}
<table>
<thead><tr>
<th>correlation_id</th><th>flow_id</th><th>events</th><th>merkle root</th>
<th>closed</th><th>closure</th><th>snapshot</th>
</tr></thead>
<tbody>
{{range .Rows}}
<tr>
<td><code>{{.CorrelationID}}</code></td>
<td><code>{{.FlowID}}</code></td>
<td>{{.EventCount}}</td>
<td><code>{{.FlowMerkleRoot}}</code></td>
<td>{{.WindowClosedAt}}</td>
<td>{{.ClosureReason}}</td>
<td><code>{{.SnapshotURI}}</code></td>
</tr>
{{end}}
</tbody></table>
{{else}}<p class="muted">No flows yet. POST execution events to ingest.</p>{{end}}
</body></html>
`

var dashboardTmpl = template.Must(template.New("dash").Parse(dashboardPage))

type dashboardView struct {
	Err  string
	Rows []dashboardRow
}

// LocalDashboardHandler serves a minimal HTML dashboard for flows in the
// local SQLite database (default :9789).
func LocalDashboardHandler(db *sql.DB) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/" {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		view := dashboardView{}
		rows, err := db.Query(`
			SELECT tenant_id, flow_id, correlation_id,
				COALESCE(event_count, 0), COALESCE(flow_merkle_root, ''),
				COALESCE(window_closed_at, ''), COALESCE(closure_reason, ''),
				COALESCE(snapshot_uri, '')
			FROM flows
			WHERE tenant_id = ?
			ORDER BY window_closed_at IS NULL ASC, window_closed_at DESC, flow_id DESC
			LIMIT 100`, LocalTenantID)
		if err != nil {
			view.Err = err.Error()
		} else {
			defer rows.Close()
			for rows.Next() {
				var row dashboardRow
				if err := rows.Scan(&row.TenantID, &row.FlowID, &row.CorrelationID,
					&row.EventCount, &row.FlowMerkleRoot, &row.WindowClosedAt,
					&row.ClosureReason, &row.SnapshotURI); err != nil {
					view.Err = err.Error()
					view.Rows = nil
					break
				}
				view.Rows = append(view.Rows, row)
			}
			if err := rows.Err(); err != nil && view.Err == "" {
				view.Err = err.Error()
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = dashboardTmpl.Execute(w, view)
	})
	return mux
}

// LocalPublicBaseURL maps a listen address like ":9787" to a browser-friendly
// origin (http://localhost:9787).
func LocalPublicBaseURL(addr string) string {
	addr = strings.TrimSpace(addr)
	switch {
	case addr == "":
		return "http://localhost:9787"
	case len(addr) > 0 && addr[0] == ':':
		return "http://localhost" + addr
	case strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://"):
		return strings.TrimSuffix(addr, "/")
	default:
		return "http://" + strings.TrimSuffix(addr, "/")
	}
}
