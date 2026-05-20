package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadReferencePackRejectsMissingReferenceID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pack.json")
	if err := os.WriteFile(path, []byte(`{"domain":"payments"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readReferencePack(path)
	if err == nil || !strings.Contains(err.Error(), "reference_id is required") {
		t.Fatalf("err=%v", err)
	}
}

func TestReadReferencePackRejectsInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pack.json")
	if err := os.WriteFile(path, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readReferencePack(path)
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoadReferencePacksEmptyDir(t *testing.T) {
	root := filepath.Join(t.TempDir(), "empty-refs")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", root)
	packs, err := loadReferencePacks()
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) != 0 {
		t.Fatalf("packs=%d", len(packs))
	}
}

func TestTenantPolicyIDEmptyReference(t *testing.T) {
	got := tenantPolicyID("", "tnt_x")
	if got != "tnt_x.policy" {
		t.Fatalf("got %q", got)
	}
}
