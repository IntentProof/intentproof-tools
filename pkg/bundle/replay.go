package bundle

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/intentproof/intentproof-tools/pkg/verifier"
)

// ReplayPolicy re-evaluates policy rules from bundle contents (flow, events,
// policy, attestations). Structural bundle checks are not repeated; callers
// should run Verify first when integrity matters.
func ReplayPolicy(b *Bundle) (*verifier.VerificationRun, error) {
	flowData, policyData, attData, err := policyInputs(b)
	if err != nil {
		return nil, err
	}
	return verifier.Verify(flowData, policyData, attData)
}

// BundledRunStatus returns the status field from run.json when present.
func BundledRunStatus(b *Bundle) (string, bool) {
	if b == nil || b.Run == nil {
		return "", false
	}
	status, ok := b.Run["status"].(string)
	return status, ok && status != ""
}

func policyInputs(b *Bundle) ([]byte, []byte, []byte, error) {
	if b == nil {
		return nil, nil, nil, fmt.Errorf("bundle is nil")
	}
	if len(b.RawFiles["policy.json"]) == 0 && b.Policy == nil {
		return nil, nil, nil, fmt.Errorf("bundle missing policy.json")
	}
	policyData := b.RawFiles["policy.json"]
	if len(policyData) == 0 {
		var err error
		policyData, err = json.Marshal(b.Policy)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("marshal policy: %w", err)
		}
	}

	flow := make(map[string]interface{}, len(b.Flow)+1)
	for k, v := range b.Flow {
		flow[k] = v
	}
	if len(b.Events) > 0 {
		flow["events"] = b.Events
	}
	flowData, err := json.Marshal(flow)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal flow: %w", err)
	}

	attData, err := marshalJSONL(b.Attestations)
	if err != nil {
		return nil, nil, nil, err
	}
	return flowData, policyData, attData, nil
}

func marshalJSONL(items []map[string]interface{}) ([]byte, error) {
	if len(items) == 0 {
		return nil, nil
	}
	var buf bytes.Buffer
	for i, item := range items {
		line, err := json.Marshal(item)
		if err != nil {
			return nil, fmt.Errorf("marshal attestation line %d: %w", i, err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}
