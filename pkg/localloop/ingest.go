package localloop

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
		addr = ":9786"
	}
	return &IngestServer{Addr: addr, DB: db, NATS: nats}
}

func (s *IngestServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	if err := StoreEvent(ctx, s.DB, ev, hash[:]); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	env := CommitEnvelope{
		TenantID:      ev.TenantID,
		EventID:       ev.EventID,
		CorrelationID: ev.CorrelationID,
		Action:        ev.Action,
	}
	if s.NATS != nil {
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
	if ev.EventID == "" || ev.TenantID == "" || ev.InstanceID == "" {
		return fmt.Errorf("missing identity fields")
	}
	if ev.ChainPosition < 1 {
		return fmt.Errorf("chain_position must be >= 1")
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
	return http.ListenAndServe(s.Addr, s)
}
