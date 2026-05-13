package policysig

import (
	"errors"
	"testing"
)

func TestNormalizeKeyStatus(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    KeyStatus
		wantErr bool
	}{
		{name: "empty defaults to active", input: "", want: KeyStatusActive},
		{name: "whitespace defaults to active", input: "   ", want: KeyStatusActive},
		{name: "lowercase active", input: "active", want: KeyStatusActive},
		{name: "uppercase active", input: "ACTIVE", want: KeyStatusActive},
		{name: "mixed case inactive", input: "Inactive", want: KeyStatusInactive},
		{name: "revoked with whitespace", input: "  revoked  ", want: KeyStatusRevoked},
		{name: "unknown returns error", input: "compromised", wantErr: true},
		{name: "near-miss returns error", input: "active1", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeKeyStatus(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil (status=%q)", tc.input, got)
				}
				if !errors.Is(err, ErrUnknownKeyStatus) {
					t.Fatalf("expected ErrUnknownKeyStatus, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestKeyStatusIsUsable(t *testing.T) {
	if !KeyStatusActive.IsUsable() {
		t.Fatal("active must be usable")
	}
	if KeyStatusInactive.IsUsable() {
		t.Fatal("inactive must not be usable")
	}
	if KeyStatusRevoked.IsUsable() {
		t.Fatal("revoked must not be usable")
	}
	// Defensive: a zero-value KeyStatus must not be usable.
	var zero KeyStatus
	if zero.IsUsable() {
		t.Fatal("zero-value KeyStatus must not be usable")
	}
}
