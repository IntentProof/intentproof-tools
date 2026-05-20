package initdetect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPythonPackageManagerNameTrimsDetail(t *testing.T) {
	if got := pythonPackageManagerName("Poetry (pyproject.toml)"); got != "poetry" {
		t.Fatalf("got=%q", got)
	}
	if got := pythonPackageManagerName("uv sync"); got != "uv" {
		t.Fatalf("got=%q", got)
	}
}

func TestPythonInstallCommandsForManagers(t *testing.T) {
	cases := map[string]string{
		"poetry": "poetry add intentproof",
		"uv":     "uv add intentproof",
		"pipenv": "pipenv install intentproof",
		"pip":    "pip install intentproof",
	}
	for pm, want := range cases {
		if got := pythonInstallCommand(pm); got != want {
			t.Fatalf("pm=%s got=%q want=%q", pm, got, want)
		}
	}
}

func TestDetectBuildkiteConfig(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "buildkite.yml"), []byte("steps:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	items := detectCI(root)
	found := false
	for _, it := range items {
		if it.Detail == "Buildkite" {
			found = true
		}
	}
	if !found {
		t.Fatalf("items=%+v", items)
	}
}
