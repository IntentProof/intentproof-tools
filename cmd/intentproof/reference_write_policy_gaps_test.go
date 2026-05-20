package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/policy"
)

func TestWriteCanonicalPolicyJSONSuccess(t *testing.T) {
	compiled, err := policy.Compile([]byte(`
policy_id: tnt_wc.demo
tenant_id: tnt_wc
policy_version: 1
spec_version: 1.0.0
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
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := writeCanonicalPolicyJSON(path, compiled); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestStampPolicyYAMLMalformedDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(":\nbad"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := stampPolicyYAML(path, "tnt_bad")
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestForkReferencePackWritePolicyJSONFailure(t *testing.T) {
	pack := referencePack{
		Dir: filepath.Join(t.TempDir(), "src"),
		Manifest: referencePackManifest{
			ReferenceID: "reference.test.writepolicy.v1",
			PolicyYAML:  "policy.yaml",
			Policy:      "policy.json",
		},
	}
	if err := os.MkdirAll(pack.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pack.Dir, "policy.yaml"), []byte(`
policy_id: tnt_src.demo
tenant_id: tnt_src
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
	dest := filepath.Join(t.TempDir(), "dest")
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	dest = filepath.Join(blocker, "nested", "fork")
	if err := forkReferencePack(pack, dest, "tnt_fork"); err == nil {
		t.Fatal("expected write policy.json failure")
	}
}

func TestRegenerateExpectedRunsListFixturesError(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.Compile([]byte(`
policy_id: tnt_x.demo
tenant_id: tnt_x
policy_version: 1
spec_version: 1.0.0
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
	if err := regenerateExpectedRuns(blocker, compiled); err == nil {
		t.Fatal("expected list fixtures error")
	}
}
