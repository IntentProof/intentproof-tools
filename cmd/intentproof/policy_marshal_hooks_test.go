package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRunPolicyLintMarshalIndentFailure(t *testing.T) {
	orig := policyCmdJSONMarshalIndent
	policyCmdJSONMarshalIndent = func(any, string, string) ([]byte, error) {
		return nil, errors.New("indent fail")
	}
	t.Cleanup(func() { policyCmdJSONMarshalIndent = orig })

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(`policy_id: tnt_lint.demo
tenant_id: tnt_lint
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
	var stdout, stderr bytes.Buffer
	if code := runPolicyLint([]string{path}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("render canonical policy")) {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunPolicyTestMarshalPolicyFailure(t *testing.T) {
	orig := policyCmdJSONMarshal
	policyCmdJSONMarshal = func(any) ([]byte, error) {
		return nil, errors.New("marshal fail")
	}
	t.Cleanup(func() { policyCmdJSONMarshal = orig })

	dir := t.TempDir()
	fixtures := filepath.Join(dir, "fixtures", "case1")
	if err := os.MkdirAll(fixtures, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"policy.yaml": `policy_id: tnt_test.demo
tenant_id: tnt_test
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 1
`,
		filepath.Join("fixtures", "case1", "flow.json"):          `{"flow_id":"f1","tenant_id":"tnt_test","flow_merkle_root":"sha256:0","events":[]}`,
		filepath.Join("fixtures", "case1", "attestations.jsonl"): "",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := runPolicyTest([]string{dir}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("marshal canonical policy")) {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunOneFixtureMarshalRunIndentFailure(t *testing.T) {
	orig := policyCmdJSONMarshalIndent
	policyCmdJSONMarshalIndent = func(any, string, string) ([]byte, error) {
		return nil, errors.New("indent fail")
	}
	t.Cleanup(func() { policyCmdJSONMarshalIndent = orig })

	dir := t.TempDir()
	for name, body := range map[string]string{
		"flow.json":          `{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000000000000000000000000000000000000000000000000000000000000000","events":[]}`,
		"attestations.jsonl": "",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := runOneFixture(dir, []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"spec_version":"1.0.0","rules":[]}`))
	if err == nil {
		t.Fatal("expected marshal indent error")
	}
}

func TestRunPolicyActivateMarshalPayloadFailure(t *testing.T) {
	orig := policyCmdJSONMarshal
	policyCmdJSONMarshal = func(any) ([]byte, error) {
		return nil, errors.New("marshal fail")
	}
	t.Cleanup(func() { policyCmdJSONMarshal = orig })

	var stdout, stderr bytes.Buffer
	if code := runPolicyActivate([]string{
		"tnt_act.demo", "1", "--scope", "global", "--tenant-id", "tnt_act",
	}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("marshal request")) {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunPolicyPublishMarshalBodyFailure(t *testing.T) {
	orig := policyCmdJSONMarshal
	policyCmdJSONMarshal = func(any) ([]byte, error) {
		return nil, errors.New("marshal fail")
	}
	t.Cleanup(func() { policyCmdJSONMarshal = orig })

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(`policy_id: tnt_pub.demo
tenant_id: tnt_pub
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
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "")
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", "")

	var stdout, stderr bytes.Buffer
	if code := runPolicyPublish([]string{path}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("marshal policy")) {
		t.Fatalf("stderr=%q", stderr.String())
	}
}
