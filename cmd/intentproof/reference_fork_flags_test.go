package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestReferenceForkFlagValidation(t *testing.T) {
	referenceRoot := writeSampleReferencePack(t)
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", referenceRoot)
	dest := filepath.Join(t.TempDir(), "dest")

	cases := []struct {
		name   string
		args   []string
		wantIn string
	}{
		{
			name:   "to without value",
			args:   []string{"reference", "fork", "reference.payments.refund-basic.v1", "--to", "--tenant", "tnt_x"},
			wantIn: "--to requires a value",
		},
		{
			name:   "tenant without value",
			args:   []string{"reference", "fork", "reference.payments.refund-basic.v1", "--to", dest, "--tenant"},
			wantIn: "--tenant requires a value",
		},
		{
			name:   "unexpected positional",
			args:   []string{"reference", "fork", "reference.payments.refund-basic.v1", "extra", "--to", dest, "--tenant", "tnt_x"},
			wantIn: "unexpected argument",
		},
		{
			name:   "unknown flag",
			args:   []string{"reference", "fork", "reference.payments.refund-basic.v1", "--to", dest, "--tenant", "tnt_x", "--nope"},
			wantIn: "unknown flag",
		},
		{
			name:   "missing tenant",
			args:   []string{"reference", "fork", "reference.payments.refund-basic.v1", "--to", dest},
			wantIn: "--tenant is required",
		},
		{
			name:   "empty reference id",
			args:   []string{"reference", "fork", "  ", "--to", dest, "--tenant", "tnt_x"},
			wantIn: "reference_id is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tc.args, &stdout, &stderr); code == 0 {
				t.Fatalf("expected failure stderr=%s", stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.wantIn) {
				t.Fatalf("stderr=%q want %q", stderr.String(), tc.wantIn)
			}
		})
	}
}
