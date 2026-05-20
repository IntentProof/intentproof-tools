package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateJSONFileMarshalError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flow.json")
	if err := os.WriteFile(path, []byte(`{"flow_id":"f1"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := updateJSONFile(path, func(doc map[string]any) {
		doc["bad"] = make(chan int)
	})
	if err == nil {
		t.Fatal("expected marshal error")
	}
}
