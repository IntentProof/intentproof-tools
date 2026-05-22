package main

import (
	"encoding/json"
	"fmt"
)

// buildEventFromSeed returns ExecutionEvent.v1 shaped JSON for differential
// canonicalization. Required fields are always present; optional nested
// payloads are derived deterministically from seed bytes.
func buildEventFromSeed(seed []byte) json.RawMessage {
	event := map[string]any{
		"schema":            "intentproof.event.v1",
		"event_id":          "evt_diff_fuzz",
		"tenant_id":         "tnt_diff",
		"instance_id":       "inst_diff",
		"correlation_id":    "corr_diff",
		"provenance_class":  "sdk_attested_evidence",
		"prev_event_hash":   "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"chain_position":    1,
		"intent":            "fuzz.intent",
		"action":            "fuzz.action",
		"status":            pickStatus(seed),
		"started_at":        "2026-05-12T00:00:00Z",
		"completed_at":      "2026-05-12T00:00:01Z",
		"duration_ms":       pickInt(seed, 1, 0, 3600000),
		"untrusted_payload": pickBool(seed, 2),
		"spec_version":      "1.0.0",
		"sdk_version":       "tools-jcs-diff-fuzz",
	}

	if v := pickOptionalNested(seed, 3); v != nil {
		event["inputs"] = v
	}
	if v := pickOptionalNested(seed, 4); v != nil {
		event["output"] = v
	}
	if attrs := pickAttributes(seed); len(attrs) > 0 {
		event["attributes"] = attrs
	}
	if pickBool(seed, 5) {
		event["signature"] = map[string]any{
			"alg":    "ed25519",
			"key_id": "inst_diff:k1",
			"value":  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
		}
	}

	if obj, ok := tryMergeSeedObject(seed); ok {
		for k, v := range obj {
			if k == "schema" {
				continue
			}
			event[k] = v
		}
		event["schema"] = "intentproof.event.v1"
	}

	raw, err := json.Marshal(event)
	if err != nil {
		panic(fmt.Sprintf("marshal generated event: %v", err))
	}
	return raw
}

func tryMergeSeedObject(seed []byte) (map[string]any, bool) {
	var obj map[string]any
	if err := json.Unmarshal(seed, &obj); err != nil || obj == nil {
		return nil, false
	}
	return obj, true
}

func pickStatus(seed []byte) string {
	if len(seed) > 0 && seed[0]%2 == 1 {
		return "error"
	}
	return "ok"
}

func pickBool(seed []byte, idx int) bool {
	if len(seed) <= idx {
		return false
	}
	return seed[idx]%2 == 1
}

func pickInt(seed []byte, idx, min, max int) int {
	if len(seed) <= idx {
		return min
	}
	span := max - min + 1
	if span <= 0 {
		return min
	}
	return min + int(seed[idx])%span
}

func pickOptionalNested(seed []byte, idx int) any {
	if len(seed) <= idx {
		return nil
	}
	return generateJSONValue(seed[idx:])
}

func pickAttributes(seed []byte) map[string]any {
	if len(seed) < 8 {
		return nil
	}
	attrs := make(map[string]any)
	for i := 0; i < 3 && i+6 < len(seed); i++ {
		key := fmt.Sprintf("attr_%d", i)
		switch seed[6+i] % 3 {
		case 0:
			attrs[key] = fmt.Sprintf("v%d", seed[6+i])
		case 1:
			attrs[key] = int(seed[6+i])
		default:
			attrs[key] = seed[6+i]%2 == 1
		}
	}
	return attrs
}

func generateJSONValue(seed []byte) any {
	if len(seed) == 0 {
		return map[string]any{}
	}
	switch seed[0] % 7 {
	case 0:
		return string(seed[1:])
	case 1:
		if len(seed) > 1 {
			return int(seed[1])
		}
		return 0
	case 2:
		if len(seed) > 1 {
			return seed[1]%2 == 1
		}
		return false
	case 3:
		return nil
	case 4:
		out := make([]any, 0, 3)
		for i := 1; i < len(seed) && i < 4; i++ {
			out = append(out, generateJSONValue(seed[i:]))
		}
		return out
	case 5:
		obj := make(map[string]any)
		for i := 1; i+1 < len(seed) && i < 10; i += 2 {
			obj[fmt.Sprintf("k%d", i)] = generateJSONValue(seed[i+1:])
		}
		return obj
	default:
		if len(seed) > 1 {
			return float64(seed[1]) / 10.0
		}
		return 0.0
	}
}
