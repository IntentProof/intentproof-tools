package policysig

import (
	"errors"
	"testing"
	"time"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ts.UTC()
}

func ptrTime(ts time.Time) *time.Time { return &ts }

func TestResolveKeyAt_NilRecord(t *testing.T) {
	err := ResolveKeyAt(nil, mustTime(t, "2026-05-12T00:00:00Z"))
	if err == nil {
		t.Fatal("expected error for nil record")
	}
	if !errors.Is(err, ErrKeyNotActive) {
		t.Fatalf("expected ErrKeyNotActive, got %v", err)
	}
}

func TestResolveKeyAt_StatusGate(t *testing.T) {
	signedAt := mustTime(t, "2026-05-12T01:00:00Z")
	activated := mustTime(t, "2026-05-12T00:00:00Z")

	cases := []struct {
		name   string
		status KeyStatus
		want   error
	}{
		{name: "active resolves", status: KeyStatusActive, want: nil},
		{name: "inactive rejected", status: KeyStatusInactive, want: ErrKeyNotUsable},
		{name: "revoked rejected", status: KeyStatusRevoked, want: ErrKeyNotUsable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &KeyRecord{
				TenantID:    "tnt_acme",
				KeyID:       "tenant:k1",
				Algorithm:   "ed25519",
				Status:      tc.status,
				ActivatedAt: activated,
			}
			err := ResolveKeyAt(rec, signedAt)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("expected nil error, got %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected errors.Is(%v), got %v", tc.want, err)
			}
		})
	}
}

func TestResolveKeyAt_WindowBoundaries(t *testing.T) {
	activated := mustTime(t, "2026-05-12T00:00:00Z")
	deactivated := mustTime(t, "2026-05-12T01:00:00Z")
	rec := &KeyRecord{
		TenantID:      "tnt_acme",
		KeyID:         "tenant:k1",
		Algorithm:     "ed25519",
		Status:        KeyStatusActive,
		ActivatedAt:   activated,
		DeactivatedAt: ptrTime(deactivated),
	}

	cases := []struct {
		name      string
		signedAt  time.Time
		wantErr   error // nil means success
		wantClass string
	}{
		{
			name:     "exactly at activated_at resolves (inclusive lower bound)",
			signedAt: activated,
			wantErr:  nil,
		},
		{
			name:      "one ns before activated_at is rejected",
			signedAt:  activated.Add(-time.Nanosecond),
			wantErr:   ErrKeyNotActive,
			wantClass: "before-window",
		},
		{
			name:     "well inside window resolves",
			signedAt: activated.Add(30 * time.Minute),
			wantErr:  nil,
		},
		{
			name:      "exactly at deactivated_at is rejected (exclusive upper bound)",
			signedAt:  deactivated,
			wantErr:   ErrKeyNotActive,
			wantClass: "after-window",
		},
		{
			name:     "one ns before deactivated_at resolves",
			signedAt: deactivated.Add(-time.Nanosecond),
			wantErr:  nil,
		},
		{
			name:      "one ns after deactivated_at is rejected",
			signedAt:  deactivated.Add(time.Nanosecond),
			wantErr:   ErrKeyNotActive,
			wantClass: "after-window",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ResolveKeyAt(rec, tc.signedAt)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("expected nil, got %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected errors.Is(%v), got %v", tc.wantErr, err)
			}
		})
	}
}

func TestResolveKeyAt_NilDeactivatedAtMeansOpenEnded(t *testing.T) {
	activated := mustTime(t, "2026-05-12T00:00:00Z")
	rec := &KeyRecord{
		TenantID:    "tnt_acme",
		KeyID:       "tenant:k1",
		Algorithm:   "ed25519",
		Status:      KeyStatusActive,
		ActivatedAt: activated,
		// DeactivatedAt is nil -> no upper bound.
	}
	// A timestamp far in the future should still resolve.
	far := activated.Add(10 * 365 * 24 * time.Hour)
	if err := ResolveKeyAt(rec, far); err != nil {
		t.Fatalf("expected nil for open-ended key, got %v", err)
	}
}

func TestResolveKeyAt_RevokedKeyInsideWindowIsRejected(t *testing.T) {
	// This is the H8 status-honored CHECK: even though the timestamp is
	// strictly inside the activation window, the key is revoked and must
	// not resolve.
	activated := mustTime(t, "2026-05-12T00:00:00Z")
	deactivated := mustTime(t, "2026-05-12T02:00:00Z")
	rec := &KeyRecord{
		TenantID:      "tnt_acme",
		KeyID:         "tenant:k1",
		Algorithm:     "ed25519",
		Status:        KeyStatusRevoked,
		ActivatedAt:   activated,
		DeactivatedAt: ptrTime(deactivated),
	}
	signedAt := mustTime(t, "2026-05-12T01:00:00Z")
	err := ResolveKeyAt(rec, signedAt)
	if err == nil {
		t.Fatal("expected revoked key inside window to be rejected")
	}
	if !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("expected ErrKeyNotUsable, got %v", err)
	}
	if errors.Is(err, ErrKeyNotActive) {
		t.Fatalf("expected status error, not window error: %v", err)
	}
}

func TestResolveKeyAt_NotYetActiveKey(t *testing.T) {
	activated := mustTime(t, "2026-05-12T00:00:00Z")
	rec := &KeyRecord{
		TenantID:    "tnt_acme",
		KeyID:       "tenant:k1",
		Algorithm:   "ed25519",
		Status:      KeyStatusActive,
		ActivatedAt: activated,
	}
	// signed_at well before activation.
	err := ResolveKeyAt(rec, activated.Add(-time.Hour))
	if !errors.Is(err, ErrKeyNotActive) {
		t.Fatalf("expected ErrKeyNotActive, got %v", err)
	}
}
