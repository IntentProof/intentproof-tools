package demo

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/localloop"
)

func TestMain(m *testing.M) {
	if os.Getenv("INTENTPROOF_SPEC_DIR") == "" {
		if spec, err := defaultSpecDirForTests(); err == nil {
			_ = os.Setenv("INTENTPROOF_SPEC_DIR", spec)
		}
	}
	restore := localloop.SetLaunchBrowserHook(func(string) error { return nil })
	code := m.Run()
	restore()
	os.Exit(code)
}

func defaultSpecDirForTests() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", os.ErrNotExist
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			for _, candidate := range []string{
				filepath.Join(dir, "..", "intentproof-spec"),
				filepath.Join(dir, "intentproof-spec"),
			} {
				if st, err := os.Stat(filepath.Join(candidate, "golden", "demo")); err == nil && st.IsDir() {
					abs, err := filepath.Abs(candidate)
					if err != nil {
						return "", err
					}
					return abs, nil
				}
			}
			return "", os.ErrNotExist
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
