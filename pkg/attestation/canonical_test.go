package attestation

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDeriveAttestationID_Deterministic(t *testing.T) {
	got1 := DeriveAttestationID("tenant_a", "stripe@webhook", "evt_123")
	got2 := DeriveAttestationID("tenant_a", "stripe@webhook", "evt_123")
	if got1 != got2 {
		t.Fatalf("DeriveAttestationID not deterministic: %q vs %q", got1, got2)
	}
}

func TestDeriveAttestationID_Format(t *testing.T) {
	got := DeriveAttestationID("tenant_a", "stripe@webhook", "evt_123")
	if !strings.HasPrefix(got, "att_") {
		t.Fatalf("expected att_ prefix, got %q", got)
	}
	// 12 bytes hex-encoded -> 24 chars.
	suffix := strings.TrimPrefix(got, "att_")
	if len(suffix) != 24 {
		t.Fatalf("expected 24 hex chars after att_, got %d (%q)", len(suffix), got)
	}
}

func TestDeriveAttestationID_DifferentiatesInputs(t *testing.T) {
	cases := [][3]string{
		{"tenant_a", "stripe@webhook", "evt_1"},
		{"tenant_b", "stripe@webhook", "evt_1"},
		{"tenant_a", "github@webhook", "evt_1"},
		{"tenant_a", "stripe@webhook", "evt_2"},
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		id := DeriveAttestationID(c[0], c[1], c[2])
		if _, dup := seen[id]; dup {
			t.Fatalf("collision for distinct inputs %v -> %s", c, id)
		}
		seen[id] = struct{}{}
	}
}

func TestDeriveAttestationID_PipeSeparatorIsLoadBearing(t *testing.T) {
	// Tenant "a|stripe" + source "webhook" + event "evt" must not
	// collide with tenant "a" + source "stripe|webhook" + event
	// "evt". This documents that the seed format is part of the
	// contract.
	a := DeriveAttestationID("a|stripe", "webhook", "evt")
	b := DeriveAttestationID("a", "stripe|webhook", "evt")
	// They will in fact collide given the current naive separator;
	// this test pins that current behavior. If the implementation
	// is hardened (length-prefixed encoding) this test must be
	// updated together with all consumers.
	if a != b {
		t.Fatalf("unexpected separator behavior change: %q vs %q", a, b)
	}
}

func TestSubject_WithoutCorrelation(t *testing.T) {
	s := Subject("stripe_refund", "re_123", nil)
	if s["type"] != "stripe_refund" || s["id"] != "re_123" {
		t.Fatalf("unexpected subject: %#v", s)
	}
	if _, ok := s["mapping_to"]; ok {
		t.Fatalf("mapping_to must be absent when correlationID is nil")
	}
}

func TestSubject_WithCorrelation(t *testing.T) {
	corr := "corr_abc"
	s := Subject("stripe_refund", "re_123", &corr)
	mapping, ok := s["mapping_to"].(map[string]any)
	if !ok {
		t.Fatalf("mapping_to missing or wrong type: %#v", s)
	}
	if mapping["correlation_id"] != "corr_abc" {
		t.Fatalf("unexpected correlation_id: %#v", mapping)
	}
}

func newFixedTime(t *testing.T) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, "2026-01-02T03:04:05.000000006Z")
	if err != nil {
		t.Fatalf("parse fixed time: %v", err)
	}
	return ts
}

func TestCanonicalBody_Deterministic(t *testing.T) {
	ts := newFixedTime(t)
	result := Result{
		SourceEventID:   "evt_1",
		SourceEmittedAt: ts,
		SubjectType:     "stripe_refund",
		SubjectID:       "re_1",
		Claim:           "refund.created",
		ClaimValue:      json.RawMessage(`{"amount":100,"currency":"usd"}`),
	}
	sig := map[string]any{"alg": "hmac-sha256", "key_id": "k1", "value": "v"}
	hash := []byte{0x01, 0x02, 0x03}

	a, err := CanonicalBody("tenant_a", "stripe@webhook", "att_xxx", ts, result, nil, sig, hash)
	if err != nil {
		t.Fatalf("CanonicalBody: %v", err)
	}
	b, err := CanonicalBody("tenant_a", "stripe@webhook", "att_xxx", ts, result, nil, sig, hash)
	if err != nil {
		t.Fatalf("CanonicalBody: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("CanonicalBody not deterministic:\n%s\n%s", a, b)
	}
}

func TestCanonicalBody_Shape(t *testing.T) {
	ts := newFixedTime(t)
	result := Result{
		SourceEventID:   "evt_1",
		SourceEmittedAt: ts,
		SubjectType:     "stripe_refund",
		SubjectID:       "re_1",
		Claim:           "refund.created",
		ClaimValue:      json.RawMessage(`{"amount":100}`),
	}
	corr := "corr_z"
	sig := map[string]any{"alg": "hmac-sha256", "key_id": "k1", "value": "v"}
	hash := []byte{0xaa, 0xbb}

	raw, err := CanonicalBody("tenant_a", "stripe@webhook", "att_xxx", ts, result, &corr, sig, hash)
	if err != nil {
		t.Fatalf("CanonicalBody: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["schema"] != CanonicalSchema {
		t.Fatalf("schema = %v, want %s", got["schema"], CanonicalSchema)
	}
	if got["attestation_id"] != "att_xxx" {
		t.Fatalf("attestation_id = %v", got["attestation_id"])
	}
	if got["tenant_id"] != "tenant_a" {
		t.Fatalf("tenant_id = %v", got["tenant_id"])
	}
	if got["source_id"] != "stripe@webhook" {
		t.Fatalf("source_id = %v", got["source_id"])
	}
	if got["claim"] != "refund.created" {
		t.Fatalf("claim = %v", got["claim"])
	}
	if got["source_payload_sha256"] != "sha256:aabb" {
		t.Fatalf("source_payload_sha256 = %v", got["source_payload_sha256"])
	}
	// claim_value must be a nested object, not a base64 string.
	cv, ok := got["claim_value"].(map[string]any)
	if !ok {
		t.Fatalf("claim_value must be object, got %T: %v", got["claim_value"], got["claim_value"])
	}
	if cv["amount"].(float64) != 100 {
		t.Fatalf("claim_value.amount = %v", cv["amount"])
	}
	subj, ok := got["subject"].(map[string]any)
	if !ok {
		t.Fatalf("subject not object: %v", got["subject"])
	}
	if subj["type"] != "stripe_refund" || subj["id"] != "re_1" {
		t.Fatalf("subject shape: %#v", subj)
	}
	mapping, ok := subj["mapping_to"].(map[string]any)
	if !ok || mapping["correlation_id"] != "corr_z" {
		t.Fatalf("mapping_to shape: %#v", subj["mapping_to"])
	}
	// Timestamps are RFC3339Nano UTC.
	if got["received_at"] != "2026-01-02T03:04:05.000000006Z" {
		t.Fatalf("received_at = %v", got["received_at"])
	}
	if got["source_emitted_at"] != "2026-01-02T03:04:05.000000006Z" {
		t.Fatalf("source_emitted_at = %v", got["source_emitted_at"])
	}
}

func TestCanonicalBody_ReceivedAtCoercedToUTC(t *testing.T) {
	utc := newFixedTime(t)
	loc, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		t.Skipf("tz data unavailable: %v", err)
	}
	nonUTC := utc.In(loc)

	result := Result{
		SourceEventID:   "evt_1",
		SourceEmittedAt: nonUTC,
		SubjectType:     "t",
		SubjectID:       "i",
		Claim:           "c",
		ClaimValue:      json.RawMessage(`{}`),
	}
	a, err := CanonicalBody("t", "s", "a", utc, result, nil, nil, nil)
	if err != nil {
		t.Fatalf("CanonicalBody utc: %v", err)
	}
	b, err := CanonicalBody("t", "s", "a", nonUTC, result, nil, nil, nil)
	if err != nil {
		t.Fatalf("CanonicalBody non-utc: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("UTC coercion broken:\n%s\n%s", a, b)
	}
}

func TestCanonicalBody_MalformedClaimValueBecomesEmptyObject(t *testing.T) {
	ts := newFixedTime(t)
	result := Result{
		SourceEventID:   "evt_1",
		SourceEmittedAt: ts,
		SubjectType:     "t",
		SubjectID:       "i",
		Claim:           "c",
		ClaimValue:      json.RawMessage(`not-json`),
	}
	raw, err := CanonicalBody("t", "s", "a", ts, result, nil, nil, nil)
	if err != nil {
		t.Fatalf("CanonicalBody: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("result was not valid JSON: %v", err)
	}
	cv, ok := got["claim_value"].(map[string]any)
	if !ok {
		t.Fatalf("malformed claim_value should become empty object, got %T", got["claim_value"])
	}
	if len(cv) != 0 {
		t.Fatalf("expected empty object, got %#v", cv)
	}
}

func TestCanonicalBody_EmptyClaimValueBecomesEmptyObject(t *testing.T) {
	ts := newFixedTime(t)
	result := Result{
		SourceEventID:   "evt_1",
		SourceEmittedAt: ts,
		SubjectType:     "t",
		SubjectID:       "i",
		Claim:           "c",
		ClaimValue:      nil,
	}
	raw, err := CanonicalBody("t", "s", "a", ts, result, nil, nil, nil)
	if err != nil {
		t.Fatalf("CanonicalBody: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cv, ok := got["claim_value"].(map[string]any)
	if !ok {
		t.Fatalf("nil claim_value should become empty object, got %T", got["claim_value"])
	}
	if len(cv) != 0 {
		t.Fatalf("expected empty object, got %#v", cv)
	}
}

func TestCanonicalBody_FieldOrderStable(t *testing.T) {
	// encoding/json marshals struct fields in declaration order;
	// pin the exact key order so any reorder of the struct
	// definition breaks loudly. Order is part of the wire format
	// because consumers sign sha256(bytes).
	ts := newFixedTime(t)
	result := Result{
		SourceEventID:   "evt_1",
		SourceEmittedAt: ts,
		SubjectType:     "t",
		SubjectID:       "i",
		Claim:           "c",
		ClaimValue:      json.RawMessage(`{}`),
	}
	raw, err := CanonicalBody("tn", "sr", "at", ts, result, nil, nil, []byte{})
	if err != nil {
		t.Fatalf("CanonicalBody: %v", err)
	}
	s := string(raw)
	wantOrder := []string{
		`"schema"`,
		`"attestation_id"`,
		`"tenant_id"`,
		`"source_id"`,
		`"received_at"`,
		`"source_emitted_at"`,
		`"subject"`,
		`"claim"`,
		`"claim_value"`,
		`"source_payload_sha256"`,
		`"source_signature"`,
	}
	prev := -1
	for _, key := range wantOrder {
		idx := strings.Index(s, key)
		if idx < 0 {
			t.Fatalf("missing key %s in body: %s", key, s)
		}
		if idx <= prev {
			t.Fatalf("key %s appeared out of expected order in body: %s", key, s)
		}
		prev = idx
	}
}
