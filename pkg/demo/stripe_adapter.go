package demo

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/attestation"
)

type stripeVerifyClockKey struct{}

func stripeWithVerifyClock(ctx context.Context, t time.Time) context.Context {
	return context.WithValue(ctx, stripeVerifyClockKey{}, t.UTC())
}

func stripeVerifyNow(ctx context.Context) time.Time {
	if ctx != nil {
		if t, ok := ctx.Value(stripeVerifyClockKey{}).(time.Time); ok {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

type stripeWebhookAdapter struct{}

func (stripeWebhookAdapter) Verify(ctx context.Context, secret string, headers map[string]string, body []byte) error {
	sigHeader := headers["stripe-signature"]
	if sigHeader == "" {
		return errors.New("missing stripe-signature")
	}
	timestamp, signatures, err := parseStripeSignature(sigHeader)
	if err != nil {
		return err
	}
	now := stripeVerifyNow(ctx).Unix()
	if delta := now - timestamp; delta < -300 || delta > 300 {
		return errors.New("stripe signature outside allowed clock window")
	}
	signedPayload := strconv.FormatInt(timestamp, 10) + "." + string(body)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signedPayload))
	expected := hex.EncodeToString(mac.Sum(nil))
	for _, got := range signatures {
		if hmac.Equal([]byte(strings.ToLower(got)), []byte(expected)) {
			return nil
		}
	}
	return errors.New("stripe signature mismatch")
}

func (stripeWebhookAdapter) Canonicalize(_ context.Context, body []byte) (attestation.Result, error) {
	var evt struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Created int64  `json:"created"`
		Data    struct {
			Object map[string]any `json:"object"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &evt); err != nil {
		return attestation.Result{}, err
	}
	if evt.ID == "" || evt.Type == "" || evt.Created <= 0 {
		return attestation.Result{}, errors.New("missing required stripe event fields")
	}
	if !isStripeRefundEventType(evt.Type) {
		return attestation.Result{}, fmt.Errorf("unsupported stripe event type for refund adapter: %s", evt.Type)
	}
	refundObj, err := extractRefundObject(evt.Type, evt.Data.Object)
	if err != nil {
		return attestation.Result{}, err
	}
	subjectID := evt.ID
	if idVal, ok := refundObj["id"].(string); ok && idVal != "" {
		subjectID = idVal
	}
	claimValue, err := json.Marshal(refundObj)
	if err != nil {
		return attestation.Result{}, err
	}
	return attestation.Result{
		SourceEventID:   evt.ID,
		SourceEmittedAt: time.Unix(evt.Created, 0).UTC(),
		SubjectType:     "stripe_refund",
		SubjectID:       subjectID,
		Claim:           evt.Type,
		ClaimValue:      claimValue,
	}, nil
}

func isStripeRefundEventType(eventType string) bool {
	if strings.HasPrefix(eventType, "refund.") {
		return true
	}
	return eventType == "charge.refunded"
}

func extractRefundObject(eventType string, obj map[string]any) (map[string]any, error) {
	if strings.HasPrefix(eventType, "refund.") {
		return obj, nil
	}
	if eventType == "charge.refunded" {
		refunds, ok := obj["refunds"].(map[string]any)
		if !ok {
			return nil, errors.New("missing refunds in charge.refunded")
		}
		data, ok := refunds["data"].([]any)
		if !ok || len(data) == 0 {
			return nil, errors.New("missing refunds.data in charge.refunded")
		}
		refund, ok := data[0].(map[string]any)
		if !ok {
			return nil, errors.New("invalid refund object in charge.refunded")
		}
		return refund, nil
	}
	return nil, fmt.Errorf("unsupported stripe event type: %s", eventType)
}

func (stripeWebhookAdapter) ReplayKey(_ context.Context, _ map[string]string, body []byte) string {
	var evt struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &evt); err == nil && evt.ID != "" {
		return evt.ID
	}
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

func (stripeWebhookAdapter) SourceSignature(headers map[string]string) map[string]any {
	return map[string]any{
		"alg":    "hmac-sha256",
		"key_id": "stripe-webhook",
		"value":  headers["stripe-signature"],
	}
}

func stripeSignatureTimestamp(headers map[string]string) (int64, error) {
	sigHeader := headers["stripe-signature"]
	if sigHeader == "" {
		return 0, errors.New("missing stripe-signature")
	}
	ts, _, err := parseStripeSignature(sigHeader)
	return ts, err
}

func parseStripeSignature(header string) (int64, []string, error) {
	parts := strings.Split(header, ",")
	var timestamp int64
	sigs := make([]string, 0)
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			ts, err := strconv.ParseInt(kv[1], 10, 64)
			if err != nil {
				return 0, nil, err
			}
			timestamp = ts
		case "v1":
			sigs = append(sigs, kv[1])
		}
	}
	if timestamp == 0 || len(sigs) == 0 {
		return 0, nil, errors.New("missing stripe signature fields")
	}
	return timestamp, sigs, nil
}
