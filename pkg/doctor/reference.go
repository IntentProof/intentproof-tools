package doctor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ResolveReferencePoliciesDir walks upward from cwd looking for reference-policies.
func ResolveReferencePoliciesDir(cwd string) (string, error) {
	if env := strings.TrimSpace(os.Getenv("INTENTPROOF_REFERENCE_POLICIES_DIR")); env != "" {
		return requireDir(env)
	}
	cwd = strings.TrimSpace(cwd)
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return "", err
		}
	}
	for dir := cwd; ; dir = filepath.Dir(dir) {
		candidates := []string{
			filepath.Join(dir, "reference-policies"),
			filepath.Join(dir, "intentproof-spec", "reference-policies"),
		}
		for _, candidate := range candidates {
			if resolved, err := requireDir(candidate); err == nil {
				return resolved, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
	}
	return "", errors.New("reference policies directory not found; set INTENTPROOF_REFERENCE_POLICIES_DIR")
}

func requireDir(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New(path + " is not a directory")
	}
	return path, nil
}
