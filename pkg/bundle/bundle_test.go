package bundle

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateAndVerifyBundle(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "test.ipb")
	files := map[string][]byte{
		"run.json": []byte(`{"events":[],"status":"ok"}`),
		"policy.json": []byte(`{"policy_id":"test"}`),
	}

	if err := CreateBundle(bundlePath, files); err != nil {
		t.Fatalf("CreateBundle: %v", err)
	}
	if _, err := os.Stat(bundlePath); err != nil {
		t.Fatalf("bundle file not created: %v", err)
	}
	if err := VerifyBundle(bundlePath); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
}

func TestVerifyMissingRunJSON(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "test.ipb")
	files := map[string][]byte{
		"policy.json": []byte(`{"policy_id":"test"}`),
	}

	if err := CreateBundle(bundlePath, files); err != nil {
		t.Fatalf("CreateBundle: %v", err)
	}

	err := VerifyBundle(bundlePath)
	if err == nil {
		t.Fatal("expected error for missing run.json")
	}
}

func TestCreateBundleInvalidPath(t *testing.T) {
	temp := t.TempDir()
	path := filepath.Join(temp, "nonexistent", "bundle.ipb")
	err := CreateBundle(path, map[string][]byte{"f": []byte("x")})
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestVerifyBundleInvalidPath(t *testing.T) {
	temp := t.TempDir()
	path := filepath.Join(temp, "nonexistent", "bundle.ipb")
	err := VerifyBundle(path)
	if err == nil {
		t.Fatal("expected error for missing bundle")
	}
}
