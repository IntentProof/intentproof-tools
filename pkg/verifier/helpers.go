package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/canon"
	"github.com/intentproof/intentproof-tools/pkg/merkle"
)

func filterAttestations(atts []attestation, claim, sourceID string) []attestation {
	matched := make([]attestation, 0)
	for _, a := range atts {
		if a.Claim != claim {
			continue
		}
		if sourceID != "" && a.SourceID != sourceID {
			continue
		}
		matched = append(matched, a)
	}
	return matched
}

func toFloat64(v interface{}) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	}
	return 0, false
}

func compareValueBound(value float64, operator string, bound float64) bool {
	switch operator {
	case "lt":
		return value < bound
	case "lte":
		return value <= bound
	case "gt":
		return value > bound
	case "gte":
		return value >= bound
	case "eq":
		return value == bound
	case "ne":
		return value != bound
	}
	return false
}

// finding builds a Finding-shaped map. reasonCode must be a vocabulary code
// from intentproof-spec semantics/reasons.json; humanSummary carries optional
// evaluator detail for operators (not part of the stable reason code).
func finding(
	r rule,
	outcome string,
	reasonCode string,
	humanSummary string,
	evidenceEventIDs []string,
	evidenceAttestationIDs []string,
) map[string]interface{} {
	if evidenceEventIDs == nil {
		evidenceEventIDs = []string{}
	}
	if evidenceAttestationIDs == nil {
		evidenceAttestationIDs = []string{}
	}
	ruleCategory := r.Category
	if reasonCode == "inconclusive.unknown.unsupported_rule_category" {
		ruleCategory = "unknown"
	}
	m := map[string]interface{}{
		"rule_id":            r.ID,
		"rule_category":      ruleCategory,
		"outcome":            outcome,
		"severity":           r.Severity,
		"reason":             reasonCode,
		"evidence_event_ids": evidenceEventIDs,
	}
	if len(evidenceAttestationIDs) > 0 {
		m["evidence_attestation_ids"] = evidenceAttestationIDs
	}
	if humanSummary != "" {
		m["human_summary"] = humanSummary
	}
	return m
}

func filterEvents(events []event, action string, where map[string]interface{}) []event {
	matched := make([]event, 0)
	for _, e := range events {
		if action != "" && e.Action != action {
			continue
		}
		if where != nil && !matchesWhere(e, where) {
			continue
		}
		matched = append(matched, e)
	}
	return matched
}

func matchesWhere(e event, where map[string]interface{}) bool {
	if status, ok := where["status"].(string); ok {
		if e.Status != status {
			return false
		}
	}
	if attr, ok := where["attribute"].(string); ok {
		if equals, ok := where["equals"]; ok {
			val, exists := e.Attributes[attr]
			if !exists || !valuesEqual(val, equals) {
				return false
			}
		}
		if inArr, ok := where["in"].([]interface{}); ok {
			val, exists := e.Attributes[attr]
			if !exists {
				return false
			}
			found := false
			for _, candidate := range inArr {
				if valuesEqual(val, candidate) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

func valuesEqual(a, b interface{}) bool {
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case float64:
		switch bv := b.(type) {
		case float64:
			return av == bv
		case int:
			return av == float64(bv)
		case int64:
			return av == float64(bv)
		}
	case int:
		switch bv := b.(type) {
		case int:
			return av == bv
		case float64:
			return float64(av) == bv
		case int64:
			return int64(av) == bv
		}
	case int64:
		switch bv := b.(type) {
		case int64:
			return av == bv
		case float64:
			return float64(av) == bv
		case int:
			return av == int64(bv)
		}
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case nil:
		return b == nil
	}
	return false
}

func eventIDs(events []event) []string {
	ids := make([]string, len(events))
	for i, e := range events {
		ids[i] = e.EventID
	}
	return ids
}

func parseEventTime(ts string) time.Time {
	if ts == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return time.Time{}
	}
	return t
}

func earliestCompletion(events []event) time.Time {
	var earliest time.Time
	for _, e := range events {
		t := parseEventTime(e.CompletedAt)
		if !t.IsZero() && (earliest.IsZero() || t.Before(earliest)) {
			earliest = t
		}
	}
	return earliest
}

func intFromInterface(v interface{}) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	}
	return 0
}

func validateAgreeAtLeast(v interface{}) (int, error) {
	if v == nil {
		return 0, fmt.Errorf("value is nil")
	}
	switch x := v.(type) {
	case int:
		if x <= 0 {
			return 0, fmt.Errorf("value must be > 0, got %d", x)
		}
		return x, nil
	case int64:
		if x <= 0 {
			return 0, fmt.Errorf("value must be > 0, got %d", x)
		}
		return int(x), nil
	case float64:
		if x <= 0 {
			return 0, fmt.Errorf("value must be > 0, got %v", x)
		}
		if x != float64(int(x)) {
			return 0, fmt.Errorf("value must be an integer, got fractional %v", x)
		}
		return int(x), nil
	default:
		return 0, fmt.Errorf("value must be numeric, got %T", v)
	}
}

func computeMerkleRoot(ids []string) string {
	sort.Strings(ids)
	leaves := make([][]byte, len(ids))
	for i, id := range ids {
		leaves[i] = []byte(id)
	}
	return merkle.RootHex(leaves)
}

func computeRunFingerprint(run *VerificationRun) (string, error) {
	canonical, err := CanonicalRunJSON(run)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// CanonicalRunJSON returns the canonical JSON representation of a run,
// excluding mutable or self-referential fields (fingerprint, signature,
// timestamps) so that signing and fingerprinting are deterministic.
func CanonicalRunJSON(run *VerificationRun) ([]byte, error) {
	raw, err := json.Marshal(run)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	delete(m, "run_fingerprint")
	delete(m, "signature")
	delete(m, "started_at")
	delete(m, "completed_at")
	return canon.Marshal(m)
}

func parseISODuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	if !strings.HasPrefix(s, "PT") {
		return 0, fmt.Errorf("unsupported duration format: %q", s)
	}
	s = s[2:]
	var total time.Duration
	for s != "" {
		idx := 0
		for idx < len(s) && (s[idx] >= '0' && s[idx] <= '9' || s[idx] == '.') {
			idx++
		}
		if idx == 0 {
			return 0, fmt.Errorf("invalid duration format: %q", s)
		}
		valStr := s[:idx]
		if idx >= len(s) {
			return 0, fmt.Errorf("missing unit in duration: %q", s)
		}
		unit := s[idx]
		s = s[idx+1:]
		val, err := parseDurationValue(valStr)
		if err != nil {
			return 0, err
		}
		switch unit {
		case 'H':
			total += time.Duration(val * float64(time.Hour))
		case 'M':
			total += time.Duration(val * float64(time.Minute))
		case 'S':
			total += time.Duration(val * float64(time.Second))
		default:
			return 0, fmt.Errorf("unsupported duration unit: %c", unit)
		}
	}
	return total, nil
}

func parseDurationValue(s string) (float64, error) {
	var val float64
	_, err := fmt.Sscanf(s, "%f", &val)
	if err != nil {
		return 0, fmt.Errorf("invalid duration value: %q", s)
	}
	return val, nil
}

func canonicalClaimValueKey(v interface{}) string {
	raw, err := canon.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%T|%v", v, v)
	}
	return string(raw)
}
