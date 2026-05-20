package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/policy"
)

func TestForkReferencePackMkdirAllError(t *testing.T) {
	root := writeSampleReferencePack(t)
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", root)
	pack, err := findReferencePack("reference.payments.refund-basic.v1")
	if err != nil {
		t.Fatal(err)
	}
	// Parent path is a file, so MkdirAll for dest parent fails.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(blocker, "nested", "dest")
	if err := forkReferencePack(pack, dest, "tnt_x"); err == nil {
		t.Fatal("expected mkdir error")
	}
}

func TestCopyDirReadError(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "ok.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(src, "secret.txt")
	if err := os.WriteFile(secret, []byte("secret"), 0o200); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "dest")
	if err := copyDir(src, dest); err == nil {
		t.Skip("platform allows reading mode 0200 file; skipping read error branch")
	}
}

func TestStampPolicyYAMLReadError(t *testing.T) {
	_, _, err := stampPolicyYAML(filepath.Join(t.TempDir(), "missing.yaml"), "tnt_x")
	if err == nil {
		t.Fatal("expected read error")
	}
}

func TestWriteCanonicalPolicyJSONWriteError(t *testing.T) {
	compiled, err := policy.Compile([]byte(`
policy_id: tnt_w.demo
tenant_id: tnt_w
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
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = writeCanonicalPolicyJSON(filepath.Join(blocker, "policy.json"), compiled)
	if err == nil {
		t.Fatal("expected write error")
	}
}

func TestRegenerateExpectedRunsSuccess(t *testing.T) {
	root := writeSampleReferencePack(t)
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", root)
	dest := filepath.Join(t.TempDir(), "fork-regen")
	var stdout, stderr bytes.Buffer
	if code := run([]string{
		"reference", "fork", "reference.payments.refund-basic.v1",
		"--to", dest, "--tenant", "tnt_regen",
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("fork: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "forked") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestAssignEvidenceActionsForbidden(t *testing.T) {
	out := map[string]string{}
	assignEvidenceActions(policy.CanonicalRule{
		Category: "forbidden",
		Spec:     map[string]any{"action": "forbidden.action"},
	}, []string{"e1"}, out)
	if out["e1"] != "forbidden.action" {
		t.Fatalf("out=%v", out)
	}
}

func TestEnrichForkedFixtureNoMatchingRule(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fixture")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "flow.json"), []byte(`{
  "flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0",
  "events":[{"event_id":"evt_a","action":"placeholder","status":"ok",
    "started_at":"2020-01-01T00:00:00Z","completed_at":"2020-01-01T00:00:01Z"}]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "expected-run.json"), []byte(`{
  "findings":[{"rule_id":"missing","reason":"pass","evidence_event_ids":["evt_a"]}]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.Compile([]byte(`
policy_id: tnt_nomatch.demo
tenant_id: tnt_nomatch
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
	if err := enrichForkedFixture(dir, compiled); err != nil {
		t.Fatal(err)
	}
}
