package localloop

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStartEmbeddedNATSRejectsFileRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(root, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := StartEmbeddedNATS(root)
	if err == nil {
		t.Fatal("expected error")
	}
}
