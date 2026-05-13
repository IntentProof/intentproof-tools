package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

func TestPolicyCompilerMatchesSpecSchema(t *testing.T) {
	specDir := os.Getenv("INTENTPROOF_SPEC_DIR")
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
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}

	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("policy.v1.schema.json", bytes.NewReader(schemaBytes)); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	schema, err := compiler.Compile("policy.v1.schema.json")
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

	if err := schema.Validate(doc); err != nil {
		t.Fatalf("compiled policy does not validate against spec schema: %v", err)
	}
}
