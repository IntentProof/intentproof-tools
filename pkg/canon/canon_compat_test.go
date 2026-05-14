package canon

import (
	"testing"
)

// TestDomainCanonicalizationCompat verifies that canon.Marshal produces
// the same canonical bytes previously emitted by ad-hoc json.Marshal-based
// normalization for representative samples from each retrofitted domain.
func TestDomainCanonicalizationCompat(t *testing.T) {
	cases := []struct {
		name     string
		input    any
		wantHash string
	}{
		{
			name: "policy_body",
			input: map[string]any{
				"schema":         "intentproof.policy.v1",
				"policy_id":      "tnt.test",
				"policy_version": 1,
				"tenant_id":      "tnt",
				"spec_version":   "1.0.0",
				"scope":          map[string]any{"any_event_action_in": []string{"a"}},
				"rules": []any{
					map[string]any{
						"id":       "r1",
						"category": "required",
						"severity": "high",
						"spec":     map[string]any{"action": "a"},
					},
				},
			},
			wantHash: "7ffa54b2f15b9ab936a94eb3926a79bde8f66b0a81d0fee69b6c9d2c6a2fb07b",
		},
		{
			name: "event_body",
			input: map[string]any{
				"schema":          "intentproof.event.v1",
				"event_id":        "evt_123",
				"tenant_id":       "tnt_acme",
				"instance_id":     "inst_123",
				"correlation_id":  "corr_123",
				"prev_event_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
				"chain_position":  1,
				"intent":          "Refund customer",
				"action":          "payments.stripe.refunds.create",
				"status":          "ok",
				"started_at":      "2026-05-11T10:00:00Z",
				"completed_at":    "2026-05-11T10:00:01Z",
				"duration_ms":     1000,
				"inputs":          map[string]any{"amount_cents": 4999},
				"output":          map[string]any{"refund_id": "re_123"},
				"error":           nil,
				"attributes":      map[string]any{"intentproof.mode": "full"},
				"spec_version":    "1.0.0",
				"sdk_version":     "node@1.0.0",
			},
			wantHash: "61b7854e9dd06a62cef376d8534b673404f463b0cb5ab6e4a16d8355a1b84615",
		},
		{
			name: "bundle_manifest",
			input: map[string]any{
				"schema":                  "intentproof.bundle.manifest.v1",
				"bundle_id":               "bundle_f1",
				"created_at":              "2026-05-12T00:00:00Z",
				"flow_id":                 "f1",
				"tenant_id":               "tnt",
				"files":                   []any{map[string]any{"path": "flow.json", "sha256": "sha256:abc"}},
				"event_merkle_root":       "sha256:def",
				"attestation_merkle_root": "sha256:ghi",
			},
			wantHash: "d23ef437013795a52f1f27347f5c2c2eaf08f9e681279e302ca5168049f7ef2a",
		},
		{
			name: "verification_run",
			input: map[string]any{
				"schema":              "intentproof.run.v1",
				"run_id":              "run_f1",
				"tenant_id":           "tnt",
				"flow_id":             "f1",
				"flow_merkle_root":    "sha256:abc",
				"policy_id":           "p1",
				"policy_version":      1,
				"policy_fingerprint":  "sha256:fp",
				"verifier_version":    "1.0.0",
				"verifier_build_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
				"attestation_set": map[string]any{
					"ids":         []string{},
					"merkle_root": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				},
				"status": "pass",
				"summary": map[string]any{
					"outcome_counts":  map[string]int{"pass": 0, "fail": 0, "inconclusive": 0},
					"severity_counts": map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
				},
				"findings": []any{},
			},
			wantHash: "e353eeeadd82bf00be261241ba3e82b15f31bc88dca8132f48714ede86c5df66",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			canonical, err := Marshal(tc.input)
			if err != nil {
				t.Fatalf("Marshal error: %v", err)
			}
			gotHash := sha256Hex(canonical)
			if gotHash != tc.wantHash {
				t.Fatalf("hash mismatch for %s:\n  canonical = %s\n  want = %s\n  got  = %s",
					tc.name, string(canonical), tc.wantHash, gotHash)
			}
		})
	}
}
