package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

func TestPolicyCompilerMatchesSpecSchema(t *testing.T) {
	specDir := resolveSpecDir(t)
	if specDir == "" {
		t.Skip("set INTENTPROOF_SPEC_DIR to run spec conformance test")
	}

	result, err := Compile([]byte(`
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: required-execute
    type: required
    action: payments.stripe.refunds.create
    min: 1
    where:
      status: ok
`))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	schemaPath := filepath.Join(specDir, "schema", "policy.v1.schema.json")
	compiler := jsonschema.NewCompiler()
	for _, schemaFile := range listSchemaFiles(t, filepath.Join(specDir, "schema")) {
		schemaBytes, err := os.ReadFile(schemaFile)
		if err != nil {
			t.Fatalf("read schema: %v", err)
		}
		schemaBytes = sanitizeSpecSchemaForGoValidator(t, schemaBytes)
		schemaID := schemaResourceID(t, schemaFile, schemaBytes)
		if err := compiler.AddResource(schemaID, bytes.NewReader(schemaBytes)); err != nil {
			t.Fatalf("add schema resource %s: %v", schemaID, err)
		}
	}
	policySchemaID := schemaResourceID(
		t,
		schemaPath,
		sanitizeSpecSchemaForGoValidator(t, mustReadFile(t, schemaPath)),
	)
	schema, err := compiler.Compile(policySchemaID)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}

	rawPolicy, err := json.Marshal(result.Policy)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	var doc any
	if err := json.Unmarshal(rawPolicy, &doc); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}
	if policyDoc, ok := doc.(map[string]any); ok {
		policyDoc["provenance_class"] = "platform_attested"
	}

	if err := schema.Validate(doc); err != nil {
		t.Fatalf("compiled policy does not validate against spec schema: %v", err)
	}
}

func resolveSpecDir(t *testing.T) string {
	t.Helper()
	env := os.Getenv("INTENTPROOF_SPEC_DIR")
	if env == "" {
		return ""
	}
	if filepath.IsAbs(env) {
		return env
	}
	modRoot, err := moduleRoot()
	if err != nil {
		t.Fatalf("resolve INTENTPROOF_SPEC_DIR: %v", err)
	}
	return filepath.Join(modRoot, env)
}

func moduleRoot() (string, error) {
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return "", err
	}
	modPath := strings.TrimSpace(string(out))
	if modPath == "" || modPath == "/dev/null" {
		return "", fmt.Errorf("go env GOMOD: no module root")
	}
	return filepath.Dir(modPath), nil
}

func schemaResourceID(t *testing.T, schemaPath string, schemaBytes []byte) string {
	t.Helper()
	var schema map[string]any
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatalf("parse schema %s: %v", schemaPath, err)
	}
	if id, ok := schema["$id"].(string); ok && id != "" {
		return id
	}
	return filepath.Base(schemaPath)
}

func listSchemaFiles(t *testing.T, schemaDir string) []string {
	t.Helper()
	entries, err := os.ReadDir(schemaDir)
	if err != nil {
		t.Fatalf("read schema dir: %v", err)
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		paths = append(paths, filepath.Join(schemaDir, entry.Name()))
	}
	sort.Strings(paths)
	return paths
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}

func sanitizeSpecSchemaForGoValidator(t *testing.T, schemaBytes []byte) []byte {
	t.Helper()
	var schema map[string]any
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	if defs, ok := schema["$defs"].(map[string]any); ok {
		if duration, ok := defs["Iso8601Duration"].(map[string]any); ok {
			delete(duration, "pattern")
		}
	}
	out, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	return out
}
