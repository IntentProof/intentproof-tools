package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileInvalidYAML(t *testing.T) {
	_, err := Compile([]byte(":\n\tbad"))
	if err == nil || !strings.Contains(err.Error(), "parse yaml") {
		t.Fatalf("err=%v", err)
	}
}

func TestCompileMissingPolicyID(t *testing.T) {
	_, err := Compile([]byte(`
tenant_id: tnt
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 1
`))
	if err == nil || !strings.Contains(err.Error(), "policy_id is required") {
		t.Fatalf("err=%v", err)
	}
}

func TestCompileMissingTenantAndScope(t *testing.T) {
	_, err := Compile([]byte(`
policy_id: orphan
spec_version: 1.0.0
rules: []
`))
	if err == nil {
		t.Fatal("expected tenant or scope error")
	}
}

func TestCompileDuplicateRuleIDParseErrors(t *testing.T) {
	_, err := Compile([]byte(`
policy_id: tnt_dup.demo
tenant_id: tnt_dup
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 1
  - id: r1
    type: required
    action: demo.action
    min: 1
`))
	if err == nil || !strings.Contains(err.Error(), "duplicate rule id") {
		t.Fatalf("err=%v", err)
	}
}

func TestCompileFileMissing(t *testing.T) {
	_, err := CompileFile(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatal("expected read error")
	}
}

func TestCompileFileSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(`
policy_id: tnt_file.demo
tenant_id: tnt_file
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 1
`), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := CompileFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if result.Fingerprint == "" {
		t.Fatal("expected fingerprint")
	}
}

func TestCompileDefaultSpecVersion(t *testing.T) {
	result, err := Compile([]byte(`
policy_id: tnt_def.demo
tenant_id: tnt_def
policy_version: 0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 1
`))
	if err != nil {
		t.Fatal(err)
	}
	if result.Policy.SpecVersion != "1.0.0" {
		t.Fatalf("spec=%s", result.Policy.SpecVersion)
	}
	if result.Policy.PolicyVersion != 1 {
		t.Fatalf("version=%d", result.Policy.PolicyVersion)
	}
}
