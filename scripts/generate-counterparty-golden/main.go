// Command generate-counterparty-golden writes the deterministic counterparty
// golden bundle and expected intentproof-verify stdout hash.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/bundle"
	"github.com/intentproof/intentproof-tools/pkg/policysig"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <output-dir>\n", filepath.Base(os.Args[0]))
		os.Exit(2)
	}
	outDir := os.Args[1]
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fatal(err)
	}

	flowJSON := []byte(`{
  "flow_id": "flow_counterparty_refund",
  "tenant_id": "tnt_acme_demo",
  "flow_merkle_root": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "correlation_id": "corr_refund_2026q1_0042",
  "events": []
}`)
	eventsJSONL := []byte(`{"event_id":"evt_001","correlation_id":"corr_refund_2026q1_0042","action":"stripe.refund.create","status":"ok","subject_email_hash":"sha256:7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc95065aa5673af9a"}
{"event_id":"evt_002","correlation_id":"corr_refund_2026q1_0042","action":"notify.customer","status":"ok","subject_email_hash":"sha256:7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc95065aa5673af9a"}
`)
	policyJSON := []byte(`{
  "policy_id": "pol_refund_counterparty",
  "tenant_id": "tnt_acme_demo",
  "policy_version": 1,
  "spec_version": "1.0.0",
  "rules": [
    {"kind": "require_action", "action": "stripe.refund.create", "severity": "fail"}
  ]
}`)
	runJSON := []byte(`{
  "run_id": "run_counterparty_refund",
  "flow_id": "flow_counterparty_refund",
  "tenant_id": "tnt_acme_demo",
  "status": "pass",
  "reason": "policy.eval_pass",
  "findings": []
}`)

	var policy map[string]any
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		fatal(err)
	}
	policyFP, err := policysig.ComputeFingerprint(policy)
	if err != nil {
		fatal(err)
	}

	var buf bytes.Buffer
	err = bundle.Create(&buf, bundle.CreateOptions{
		BundleID:          "bnd_counterparty_refund",
		FlowID:            "flow_counterparty_refund",
		TenantID:          "tnt_acme_demo",
		FlowJSON:          flowJSON,
		EventsJSONL:       eventsJSONL,
		AttestationsJSONL: nil,
		PolicyJSON:        policyJSON,
		RunJSON:           runJSON,
		CreatedAt:         time.Date(2026, 5, 15, 14, 30, 0, 0, time.UTC),
		VerificationProfile: &bundle.VerificationProfile{
			SpecVersion:     "v0.0.0-source-verified.1",
			VerifierVersion: "dev",
			PolicyVersions:  []string{policyFP},
			ExportProfile:   "counterparty",
			FlowSnapshotID:  "flow_counterparty_refund",
			RunID:           "run_counterparty_refund",
		},
	})
	if err != nil {
		fatal(err)
	}

	bundlePath := filepath.Join(outDir, "counterparty-refund.proof.tar.zst")
	if err := os.WriteFile(bundlePath, buf.Bytes(), 0o644); err != nil {
		fatal(err)
	}

	res, err := bundle.Verify(bytes.NewReader(buf.Bytes()), nil)
	if err != nil {
		fatal(err)
	}
	if res.Status != "pass" {
		fatal(fmt.Errorf("bundle verify status=%s reason=%s", res.Status, res.Reason))
	}

	stdout := formatVerifyStdout(res)
	sum := sha256.Sum256([]byte(stdout))
	hashPath := filepath.Join(outDir, "expected-verify-stdout-sha256.txt")
	if err := os.WriteFile(hashPath, []byte(hex.EncodeToString(sum[:])+"\n"), 0o644); err != nil {
		fatal(err)
	}

	fmt.Printf("wrote %s\n", bundlePath)
	fmt.Printf("wrote %s\n", hashPath)
}

func formatVerifyStdout(res *bundle.VerifyResult) string {
	marker := "✓ pass"
	if res.Status != "pass" {
		marker = "✗ fail"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n", marker, res.Reason)
	for _, finding := range res.Findings {
		fmt.Fprintf(&b, "- %s\n", finding)
	}
	return b.String()
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
