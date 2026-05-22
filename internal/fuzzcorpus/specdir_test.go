package fuzzcorpus

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDirFromAbsoluteSpecEnv(t *testing.T) {
	specRoot := t.TempDir()
	corpus := filepath.Join(specRoot, "golden", "fuzz-corpora", "canon")
	if err := os.MkdirAll(corpus, 0o755); err != nil {
		t.Fatalf("mkdir corpus: %v", err)
	}

	got, err := dir(specRoot, "canon")
	if err != nil {
		t.Fatalf("dir: %v", err)
	}
	want, err := filepath.Abs(corpus)
	if err != nil {
		t.Fatalf("abs corpus: %v", err)
	}
	if got != want {
		t.Fatalf("dir() = %q, want %q", got, want)
	}
}

func TestDirFromRelativeSpecEnv(t *testing.T) {
	modRoot, err := moduleRoot()
	if err != nil {
		t.Fatalf("moduleRoot: %v", err)
	}
	specRoot := t.TempDir()
	corpus := filepath.Join(specRoot, "golden", "fuzz-corpora", "policy")
	if err := os.MkdirAll(corpus, 0o755); err != nil {
		t.Fatalf("mkdir corpus: %v", err)
	}
	rel, err := filepath.Rel(modRoot, specRoot)
	if err != nil {
		t.Fatalf("rel path: %v", err)
	}

	got, err := dir(rel, "policy")
	if err != nil {
		t.Fatalf("dir: %v", err)
	}
	want, err := filepath.Abs(corpus)
	if err != nil {
		t.Fatalf("abs corpus: %v", err)
	}
	if got != want {
		t.Fatalf("dir() = %q, want %q", got, want)
	}
}

func TestDirIntegrationUsesEnv(t *testing.T) {
	specRoot := t.TempDir()
	corpus := filepath.Join(specRoot, "golden", "fuzz-corpora", "canon")
	if err := os.MkdirAll(corpus, 0o755); err != nil {
		t.Fatalf("mkdir corpus: %v", err)
	}
	t.Setenv("INTENTPROOF_SPEC_DIR", specRoot)

	got := Dir(t, "canon")
	want, err := filepath.Abs(corpus)
	if err != nil {
		t.Fatalf("abs corpus: %v", err)
	}
	if got != want {
		t.Fatalf("Dir() = %q, want %q", got, want)
	}
}

func TestCorpusDirMissingSubdir(t *testing.T) {
	specRoot := t.TempDir()
	corpusRoot := filepath.Join(specRoot, "golden", "fuzz-corpora")
	if err := os.MkdirAll(corpusRoot, 0o755); err != nil {
		t.Fatalf("mkdir corpus root: %v", err)
	}
	_, err := corpusDir(specRoot, "missing")
	if err == nil {
		t.Fatal("expected error for missing corpus subdir")
	}
}

func TestDirMissingSubdir(t *testing.T) {
	specRoot := t.TempDir()
	corpusRoot := filepath.Join(specRoot, "golden", "fuzz-corpora")
	if err := os.MkdirAll(corpusRoot, 0o755); err != nil {
		t.Fatalf("mkdir corpus root: %v", err)
	}
	_, err := dir(specRoot, "missing")
	if err == nil {
		t.Fatal("expected error for missing corpus subdir")
	}
}

func TestSpecRootFromEnvInvalid(t *testing.T) {
	_, err := specRootFromEnv(t.TempDir())
	if err == nil {
		t.Fatal("expected error for spec dir without corpora")
	}
}

func TestSpecRootFromEnvRelativeWithoutModule(t *testing.T) {
	withIsolatedWorkdir(t, func(t *testing.T) {
		_, err := specRootFromEnv("relative/spec")
		if err == nil {
			t.Fatal("expected error resolving relative spec dir outside module")
		}
	})
}

func TestSpecRootFromEnvNotFound(t *testing.T) {
	withIsolatedModule(t, func(t *testing.T) {
		_, err := specRootFromEnv("")
		if !errors.Is(err, errSpecCorpusNotFound) {
			t.Fatalf("specRootFromEnv(\"\") = %v, want errSpecCorpusNotFound", err)
		}
	})
}

func TestDirSkipWhenSpecUnavailable(t *testing.T) {
	withIsolatedModule(t, func(t *testing.T) {
		t.Setenv("INTENTPROOF_SPEC_DIR", "")
		Dir(t, "canon")
	})
}

func TestModuleRoot(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("moduleRoot: %v", err)
	}
	if root == "" {
		t.Fatal("expected non-empty module root")
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("go.mod under module root: %v", err)
	}
}

func TestSpecRootMonorepoFallback(t *testing.T) {
	modRoot, err := moduleRoot()
	if err != nil {
		t.Fatalf("moduleRoot: %v", err)
	}
	for _, candidate := range []string{
		filepath.Join(modRoot, "intentproof-spec"),
		filepath.Join(modRoot, "..", "intentproof-spec"),
		filepath.Join(modRoot, "..", "..", "intentproof-spec"),
	} {
		corpusRoot := filepath.Join(candidate, "golden", "fuzz-corpora")
		if st, err := os.Stat(corpusRoot); err != nil || !st.IsDir() {
			continue
		}
		root, err := specRootFromEnv("")
		if err != nil {
			t.Fatalf("specRootFromEnv: %v", err)
		}
		if _, err := os.Stat(filepath.Join(root, "golden", "fuzz-corpora")); err != nil {
			t.Fatalf("corpus root under fallback: %v", err)
		}
		return
	}
	t.Skip("intentproof-spec fuzz corpora not present beside module root")
}

func withIsolatedWorkdir(t *testing.T, fn func(*testing.T)) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir temp: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(wd); err != nil {
			t.Errorf("restore workdir: %v", err)
		}
	})
	fn(t)
}

func withIsolatedModule(t *testing.T, fn func(*testing.T)) {
	t.Helper()
	withIsolatedWorkdir(t, func(t *testing.T) {
		tmp, err := os.Getwd()
		if err != nil {
			t.Fatalf("getwd: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte("module example.com/isolated\n"), 0o644); err != nil {
			t.Fatalf("write go.mod: %v", err)
		}
		fn(t)
	})
}
