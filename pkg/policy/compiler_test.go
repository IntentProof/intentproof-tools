package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCompileValidPolicy(t *testing.T) {
	raw := []byte(`
policy_id: tnt_acme.refund-flow
policy_version: 4
tenant_id: tnt_acme
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: required-execute
    type: required
    action: payments.stripe.refunds.create
    min: 1
    where: { status: ok }
  - id: forbid-double-refund
    type: forbidden
    severity: critical
    action: payments.stripe.refunds.create
    after: payments.stripe.refunds.create
    where_predecessor: { status: ok }
  - id: ordering
    type: ordering
    before: payments.stripe.refunds.create
    after: customer.notify
  - id: temporal-execute-to-notify
    type: temporal
    from: { action: payments.stripe.refunds.create, anchor: completed_at }
    to: { action: customer.notify, anchor: started_at }
    max: PT5M
  - id: consensus-stripe-ack
    type: consensus
    claim: refund.acknowledged
    sources:
      - kind: internal
        action: payments.stripe.refunds.create
        where: { status: ok }
      - kind: external
        source_id: stripe@webhook
    threshold:
      unanimous: true
`)

	result, err := Compile(raw)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if result.Policy.Schema != "intentproof.policy.v1" {
		t.Fatalf("unexpected schema: %s", result.Policy.Schema)
	}
	if !strings.HasPrefix(result.Fingerprint, "sha256:") {
		t.Fatalf("unexpected fingerprint: %s", result.Fingerprint)
	}
	if result.Policy.PolicyFingerprint != result.Fingerprint {
		t.Fatalf("fingerprint mismatch")
	}
	if len(result.Policy.Scope.AnyEventActionIn) != 1 {
		t.Fatalf("unexpected scope actions: %+v", result.Policy.Scope.AnyEventActionIn)
	}
	consensus := result.Policy.Rules[4]
	sources := consensus.Spec["sources"].([]map[string]any)
	if sources[0]["kind"] != "intentproof_action" {
		t.Fatalf("expected internal source normalized, got: %v", sources[0]["kind"])
	}
}

func TestCompileRejectsDuplicateRuleIDs(t *testing.T) {
	t.Run("exact duplicate id", func(t *testing.T) {
		raw := wrap(`  - id: foo
    type: required
    action: demo.action
    min: 1
  - id: foo
    type: forbidden
    action: demo.action
`)
		_, err := Compile(raw)
		if err == nil || !strings.Contains(err.Error(), `duplicate rule id "foo"`) {
			t.Fatalf("expected duplicate id error, got: %v", err)
		}
	})

	t.Run("duplicate after trim ignores surrounding space", func(t *testing.T) {
		raw := wrap(`  - id: "  foo  "
    type: required
    action: demo.action
    min: 1
  - id: foo
    type: forbidden
    action: demo.action
`)
		_, err := Compile(raw)
		if err == nil || !strings.Contains(err.Error(), `duplicate rule id "foo"`) {
			t.Fatalf("expected duplicate id error, got: %v", err)
		}
	})
}

func TestCompileAcceptsDistinctRuleIDs(t *testing.T) {
	raw := wrap(`  - id: r1
    type: required
    action: demo.action
    min: 1
  - id: r2
    type: forbidden
    action: demo.action
`)
	if _, err := Compile(raw); err != nil {
		t.Fatalf("Compile: %v", err)
	}
}

func TestCompileRejectsWhitespaceOnlyRuleID(t *testing.T) {
	raw := wrap(`  - id: "   "
    type: required
    action: demo.action
    min: 1
`)
	_, err := Compile(raw)
	if err == nil || !strings.Contains(err.Error(), "rule id is required") {
		t.Fatalf("expected rule id error, got: %v", err)
	}
}

func TestCompileRejectsDuplicateWhitespaceOnlyRuleIDs(t *testing.T) {
	// Two rules whose raw ids are different but trim to empty: first fails
	// before duplicate logic; second would be wrong if empty ids slipped through.
	raw := wrap(`  - id: "  "
    type: required
    action: demo.action
    min: 1
  - id: "\t"
    type: forbidden
    action: demo.action
`)
	_, err := Compile(raw)
	if err == nil || !strings.Contains(err.Error(), "rule id is required") {
		t.Fatalf("expected rule id error, got: %v", err)
	}
}

func TestCompileRejectsCardinalityMutualExclusion(t *testing.T) {
	raw := []byte(`
policy_id: tnt_acme.bad
tenant_id: tnt_acme
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: c1
    type: cardinality
    action: demo.action
    exactly: 1
    min: 1
`)

	_, err := Compile(raw)
	if err == nil || !strings.Contains(err.Error(), "exactly conflicts") {
		t.Fatalf("expected mutual exclusion error, got: %v", err)
	}
}

func TestCompileRejectsUnknownCategoryWithCanonicalSpec(t *testing.T) {
	raw := wrap(`  - id: typo
    category: requred
    spec:
      action: demo.action
      min: 1
`)

	_, err := Compile(raw)
	if err == nil || !strings.Contains(err.Error(), "unknown rule category: requred") {
		t.Fatalf("expected unknown category error, got: %v", err)
	}
}

// wrap embeds a YAML rule body inside a minimal valid policy envelope so
// tests can focus on per-rule validation.
func wrap(rules string) []byte {
	return []byte(`
policy_id: tnt_acme.test
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
` + rules)
}

func TestCompileSeverityValidation(t *testing.T) {
	t.Run("accepts each allowed severity", func(t *testing.T) {
		for _, sev := range []string{"info", "low", "medium", "high", "critical"} {
			raw := wrap(`  - id: r1
    type: required
    action: demo.action
    severity: ` + sev + `
    min: 1
`)
			if _, err := Compile(raw); err != nil {
				t.Fatalf("severity %q rejected: %v", sev, err)
			}
		}
	})

	t.Run("rejects unknown severity with offending value", func(t *testing.T) {
		raw := wrap(`  - id: r1
    type: required
    action: demo.action
    severity: catastrophic
    min: 1
`)
		_, err := Compile(raw)
		if err == nil {
			t.Fatal("expected error for bogus severity")
		}
		if !strings.Contains(err.Error(), `"catastrophic"`) {
			t.Fatalf("error should include offending value, got: %v", err)
		}
	})
}

func TestCompileForbiddenPredecessorMutex(t *testing.T) {
	t.Run("rejects both predecessor selectors set", func(t *testing.T) {
		raw := wrap(`  - id: f1
    type: forbidden
    action: demo.action
    after: demo.action
    where_predecessor: { status: ok }
    without_predecessor: demo.cancel
`)
		_, err := Compile(raw)
		if err == nil || !strings.Contains(err.Error(), "cannot set both") {
			t.Fatalf("expected mutex error, got: %v", err)
		}
	})

	t.Run("rejects where_predecessor without after", func(t *testing.T) {
		raw := wrap(`  - id: f1
    type: forbidden
    action: demo.action
    where_predecessor: { status: ok }
`)
		_, err := Compile(raw)
		if err == nil || !strings.Contains(err.Error(), "requires after") {
			t.Fatalf("expected requires-after error, got: %v", err)
		}
	})

	t.Run("rejects without_predecessor without after", func(t *testing.T) {
		raw := wrap(`  - id: f1
    type: forbidden
    action: demo.action
    without_predecessor: demo.cancel
`)
		_, err := Compile(raw)
		if err == nil || !strings.Contains(err.Error(), "requires after") {
			t.Fatalf("expected requires-after error, got: %v", err)
		}
	})

	t.Run("accepts forbidden with after and one predecessor selector", func(t *testing.T) {
		raw := wrap(`  - id: f1
    type: forbidden
    action: demo.action
    after: demo.action
    where_predecessor: { status: ok }
`)
		if _, err := Compile(raw); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	// An explicitly empty where_predecessor map must count as "set" for the
	// mutex and after-requirement checks; otherwise users could bypass the
	// guard by writing `where_predecessor: {}`.
	t.Run("treats empty where_predecessor map as set for requires-after", func(t *testing.T) {
		raw := wrap(`  - id: f1
    type: forbidden
    action: demo.action
    where_predecessor: {}
`)
		_, err := Compile(raw)
		if err == nil || !strings.Contains(err.Error(), "requires after") {
			t.Fatalf("expected requires-after error, got: %v", err)
		}
	})

	t.Run("treats empty where_predecessor map as set for mutex", func(t *testing.T) {
		raw := wrap(`  - id: f1
    type: forbidden
    action: demo.action
    after: demo.action
    where_predecessor: {}
    without_predecessor: demo.cancel
`)
		_, err := Compile(raw)
		if err == nil || !strings.Contains(err.Error(), "cannot set both") {
			t.Fatalf("expected mutex error, got: %v", err)
		}
	})
}

// TestCompileWhereJSONSafe verifies that compiled rule specs marshal cleanly
// to JSON. This guards against the historical map[interface{}]interface{}
// failure mode from yaml.v2-style decoders.
func TestCompileWhereJSONSafe(t *testing.T) {
	raw := wrap(`  - id: r1
    type: required
    action: demo.action
    min: 1
    where:
      status: ok
      nested:
        deep:
          deeper: value
        list:
          - a
          - b: c
`)
	res, err := Compile(raw)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if _, err := json.Marshal(res.Policy); err != nil {
		t.Fatalf("policy not JSON-safe: %v", err)
	}
}

// --- Positive + negative coverage per canonical rule kind. ---

func TestCompileRuleKinds(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantErrIn string // substring expected in err; empty = success
	}{
		// required
		{
			name: "required ok",
			body: `  - id: r1
    type: required
    action: demo.action
    min: 1
`,
		},
		{
			name: "required missing action",
			body: `  - id: r1
    type: required
    min: 1
`,
			wantErrIn: "required rule needs action",
		},

		// forbidden
		{
			name: "forbidden ok",
			body: `  - id: r1
    type: forbidden
    action: demo.action
`,
		},
		{
			name: "forbidden missing action",
			body: `  - id: r1
    type: forbidden
`,
			wantErrIn: "forbidden rule needs action",
		},

		// ordering
		{
			name: "ordering ok",
			body: `  - id: r1
    type: ordering
    before: demo.b
    after: demo.a
`,
		},
		{
			name: "ordering missing before",
			body: `  - id: r1
    type: ordering
    after: demo.a
`,
			wantErrIn: "ordering rule needs before and after",
		},

		// cardinality
		{
			name: "cardinality ok",
			body: `  - id: r1
    type: cardinality
    action: demo.action
    exactly: 1
`,
		},
		{
			name: "cardinality negative min",
			body: `  - id: r1
    type: cardinality
    action: demo.action
    min: -1
`,
			wantErrIn: "min must be >= 0",
		},

		// temporal
		{
			name: "temporal ok",
			body: `  - id: r1
    type: temporal
    from: { action: demo.a, anchor: completed_at }
    to: { action: demo.b, anchor: started_at }
    max: PT5M
`,
		},
		{
			name: "temporal missing max",
			body: `  - id: r1
    type: temporal
    from: { action: demo.a, anchor: completed_at }
    to: { action: demo.b, anchor: started_at }
`,
			wantErrIn: "temporal rule needs max duration",
		},

		// consensus
		{
			name: "consensus ok",
			body: `  - id: r1
    type: consensus
    claim: c.x
    sources:
      - kind: external
        source_id: s1
      - kind: external
        source_id: s2
    threshold:
      majority: true
`,
		},
		{
			name: "consensus bad threshold",
			body: `  - id: r1
    type: consensus
    claim: c.x
    sources:
      - kind: external
        source_id: s1
    threshold:
      majority: true
      unanimous: true
`,
			wantErrIn: "exactly one of",
		},

		// value_bound
		{
			name: "value_bound ok",
			body: `  - id: r1
    type: value_bound
    claim: refund.amount
    operator: lte
    value: 100
`,
		},
		{
			name: "value_bound bad operator",
			body: `  - id: r1
    type: value_bound
    claim: refund.amount
    operator: between
    value: 1
`,
			wantErrIn: "unsupported operator",
		},
		{
			name: "value_bound non-numeric value",
			body: `  - id: r1
    type: value_bound
    claim: refund.amount
    operator: lte
    value: "abc"
`,
			wantErrIn: "numeric value",
		},

		// claim_match
		{
			name: "claim_match ok",
			body: `  - id: r1
    type: claim_match
    claim: refund.status
    expected_value: succeeded
`,
		},
		{
			name: "claim_match missing expected_value",
			body: `  - id: r1
    type: claim_match
    claim: refund.status
`,
			wantErrIn: "expected_value",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile(wrap(tc.body))
			if tc.wantErrIn == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErrIn)
			}
			if !strings.Contains(err.Error(), tc.wantErrIn) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErrIn)
			}
		})
	}
}

func TestCompileValueBoundCanonicalSpec(t *testing.T) {
	raw := wrap(`  - id: r1
    type: value_bound
    claim: refund.amount
    operator: lte
    value: 250
    source_id: stripe@webhook
`)
	res, err := Compile(raw)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rule := res.Policy.Rules[0]
	if rule.Category != "value_bound" {
		t.Fatalf("category: %s", rule.Category)
	}
	if got, _ := rule.Spec["operator"].(string); got != "lte" {
		t.Fatalf("operator: %v", rule.Spec["operator"])
	}
	if got, _ := rule.Spec["value"].(float64); got != 250 {
		t.Fatalf("value: %v", rule.Spec["value"])
	}
	if got, _ := rule.Spec["source_id"].(string); got != "stripe@webhook" {
		t.Fatalf("source_id: %v", rule.Spec["source_id"])
	}
}

func TestCompileClaimMatchCanonicalSpec(t *testing.T) {
	raw := wrap(`  - id: r1
    type: claim_match
    claim: refund.status
    expected_value: succeeded
    source_id: stripe@webhook
    require_signed: true
`)
	res, err := Compile(raw)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rule := res.Policy.Rules[0]
	if rule.Category != "claim_match" {
		t.Fatalf("category: %s", rule.Category)
	}
	if rule.Spec["expected_value"] != "succeeded" {
		t.Fatalf("expected_value: %v", rule.Spec["expected_value"])
	}
	if got, _ := rule.Spec["require_signed"].(bool); !got {
		t.Fatalf("require_signed: %v", rule.Spec["require_signed"])
	}
}

// When a claim_match rule sets both require_signed and require_signed_sources
// to conflicting values, the compiler must reject the policy rather than
// silently prefer one alias.
func TestCompileClaimMatchRejectsConflictingRequireSignedAliases(t *testing.T) {
	raw := wrap(`  - id: r1
    type: claim_match
    claim: refund.status
    expected_value: succeeded
    require_signed: true
    require_signed_sources: false
`)
	_, err := Compile(raw)
	if err == nil {
		t.Fatal("expected error for conflicting aliases")
	}
	if !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("error should call out conflict, got: %v", err)
	}
}

// When both aliases agree, the policy compiles and the canonical
// `require_signed` field reflects the agreed value.
func TestCompileClaimMatchAcceptsAgreeingRequireSignedAliases(t *testing.T) {
	raw := wrap(`  - id: r1
    type: claim_match
    claim: refund.status
    expected_value: succeeded
    require_signed: true
    require_signed_sources: true
`)
	res, err := Compile(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, _ := res.Policy.Rules[0].Spec["require_signed"].(bool); !got {
		t.Fatalf("require_signed: %v", res.Policy.Rules[0].Spec["require_signed"])
	}
}

func TestNormalizeMapConvertsInterfaceKeys(t *testing.T) {
	in := map[any]any{
		"a": 1,
		"b": map[any]any{
			"c": []any{
				map[any]any{"d": "e"},
				"f",
			},
		},
		2: "stringified",
	}
	out := normalizeMap(in)
	bs, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(bs)
	for _, want := range []string{`"a":1`, `"b":{`, `"c":[`, `"d":"e"`, `"2":"stringified"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("normalized JSON missing %q: %s", want, got)
		}
	}
}
