package localloop

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// IngestServer is the HTTP server that receives ExecutionEvents.
type IngestServer struct {
	Addr string
	DB   *sql.DB
	NATS *NATSWrapper
}

// NewIngestServer creates an ingest HTTP server.
func NewIngestServer(addr string, db *sql.DB, nats *NATSWrapper) *IngestServer {
	if addr == "" {
		addr = ":9787"
	}
	return &IngestServer{Addr: addr, DB: db, NATS: nats}
}

// Handler returns the HTTP mux (health check + ingest).
func (s *IngestServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/v1/events", s.handleV1Events)
	return mux
}

func (s *IngestServer) handleV1Events(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var ev ExecutionEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := validateEvent(ev); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	hash := sha256.Sum256(canon)

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	inserted, err := StoreEvent(ctx, s.DB, ev, hash[:])
	if err != nil {
		if errors.Is(err, ErrChainConflict) {
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if inserted && s.NATS != nil {
		env := CommitEnvelope{
			TenantID:      ev.TenantID,
			EventID:       ev.EventID,
			CorrelationID: ev.CorrelationID,
			Action:        ev.Action,
		}
		if err := s.NATS.PublishEventCommitted(env); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusAccepted)
}

func validateEvent(ev ExecutionEvent) error {
	if ev.Schema != "intentproof.event.v1" {
		return fmt.Errorf("invalid schema")
	}
	if ev.EventID == "" || ev.TenantID == "" || ev.InstanceID == "" || ev.CorrelationID == "" {
		return fmt.Errorf("missing identity fields")
	}
	if ev.ChainPosition < 1 {
		return fmt.Errorf("chain_position must be >= 1")
	}
	if ev.Signature.Alg != "ed25519" || ev.Signature.Value == "" {
		return fmt.Errorf("invalid signature envelope")
	}
	if !strings.HasPrefix(ev.PrevEventHash, "sha256:") {
		return fmt.Errorf("prev_event_hash must use sha256 prefix")
	}
	hexPart := strings.TrimPrefix(ev.PrevEventHash, "sha256:")
	if len(hexPart) != 64 {
		return fmt.Errorf("prev_event_hash must be 64 hex digits after prefix")
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return fmt.Errorf("prev_event_hash invalid hex")
	}
	return nil
}

func canonicalizeWithoutSignature(ev ExecutionEvent) ([]byte, error) {
	copyEvent := ev
	copyEvent.Signature = Signature{}
	rawMap := map[string]any{}
	rawBytes, err := json.Marshal(copyEvent)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(rawBytes, &rawMap); err != nil {
		return nil, err
	}
	delete(rawMap, "signature")
	return json.Marshal(rawMap)
}

// ListenAndServe starts the ingest HTTP server.
func (s *IngestServer) ListenAndServe() error {
	return http.ListenAndServe(s.Addr, s.Handler())
}
