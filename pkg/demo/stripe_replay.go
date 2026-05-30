package demo

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/attestation"
	"github.com/intentproof/intentproof-tools/pkg/canon"
)

const stripeDemoSourceID = "stripe@demo"

// stripeDemoHMACSecret is documented in intentproof-spec/golden/demo/stripe/README.md.
const stripeDemoHMACSecret = "whsec_intentproof_demo_golden_v1"

type attestRecord struct {
	body json.RawMessage
}

type attestMemoryStore struct {
	records []attestRecord
	seen    map[string]struct{}
}

func newAttestMemoryStore() *attestMemoryStore {
	return &attestMemoryStore{seen: map[string]struct{}{}}
}

func (s *attestMemoryStore) attestationsJSONL() []byte {
	if len(s.records) == 0 {
		return nil
	}
	out := make([]byte, 0)
	for i, rec := range s.records {
		if i > 0 {
			out = append(out, '\n')
		}
		out = append(out, rec.body...)
	}
	return out
}

func replayStripeDemoAttestationIntoStore(
	store *attestMemoryStore,
	tenantID string,
	platformKey ed25519.PrivateKey,
	scenario RefundScenario,
	receivedAt time.Time,
) error {
	body := scenario.StripeBody
	headers := scenario.StripeHeaders
	var adapter stripeWebhookAdapter
	ts, err := stripeSignatureTimestamp(headers)
	if err != nil {
		return fmt.Errorf("stripe@demo headers: %w", err)
	}
	ctx := stripeWithVerifyClock(context.Background(), time.Unix(ts, 0).UTC())
	if err := adapter.Verify(ctx, stripeDemoHMACSecret, headers, body); err != nil {
		return fmt.Errorf("stripe@demo verify: %w", err)
	}
	result, err := adapter.Canonicalize(ctx, body)
	if err != nil {
		return fmt.Errorf("stripe@demo canonicalize: %w", err)
	}
	replayKey := adapter.ReplayKey(ctx, headers, body)
	rk := tenantID + "\x00" + stripeDemoSourceID + "\x00" + replayKey
	if _, ok := store.seen[rk]; ok {
		return nil
	}

	attestationID := attestation.DeriveAttestationID(tenantID, stripeDemoSourceID, result.SourceEventID)
	payloadHash := sha256.Sum256(body)
	sourceSignature := adapter.SourceSignature(headers)
	bodyJSON, err := attestation.CanonicalBody(
		tenantID, stripeDemoSourceID, attestationID, receivedAt.UTC(), result, nil, sourceSignature, payloadHash[:],
	)
	if err != nil {
		return fmt.Errorf("stripe@demo canonical body: %w", err)
	}
	digest := sha256.Sum256(bodyJSON)
	sig := ed25519.Sign(platformKey, digest[:])
	platformSignature := map[string]any{
		"alg":    "ed25519",
		"key_id": "platform-demo",
		"value":  base64.StdEncoding.EncodeToString(sig),
	}
	var bodyDoc map[string]any
	if err := json.Unmarshal(bodyJSON, &bodyDoc); err != nil {
		return fmt.Errorf("stripe@demo attestation body: %w", err)
	}
	bodyDoc["platform_signature"] = platformSignature
	wireBodyJSON, err := canon.Marshal(bodyDoc)
	if err != nil {
		return fmt.Errorf("stripe@demo marshal: %w", err)
	}
	store.seen[rk] = struct{}{}
	store.records = append(store.records, attestRecord{body: wireBodyJSON})
	return nil
}
