package verifier

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// nowFunc is swappable for deterministic tests.
var nowFunc = func() time.Time { return time.Now().UTC() }

func init() {
	if os.Getenv("INTENTPROOF_DETERMINISTIC_TIME") == "1" {
		nowFunc = func() time.Time {
			return time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
		}
	}
}

// VerificationRun is the canonical output of policy evaluation.
type VerificationRun struct {
	Schema            string                   `json:"schema"`
	RunID             string                   `json:"run_id"`
	TenantID          string                   `json:"tenant_id"`
	FlowID            string                   `json:"flow_id"`
	FlowMerkleRoot    string                   `json:"flow_merkle_root"`
	PolicyID          string                   `json:"policy_id"`
	PolicyVersion     int                      `json:"policy_version"`
	PolicyFingerprint string                   `json:"policy_fingerprint"`
	VerifierVersion   string                   `json:"verifier_version"`
	VerifierBuildHash string                   `json:"verifier_build_hash"`
	AttestationSet    AttestationSet           `json:"attestation_set"`
	StartedAt         string                   `json:"started_at"`
	CompletedAt       string                   `json:"completed_at"`
	Status            string                   `json:"status"`
	Summary           Summary                  `json:"summary"`
	Findings          []map[string]interface{} `json:"findings"`
	RunFingerprint    string                   `json:"run_fingerprint"`
	Signature         map[string]interface{}   `json:"signature"`
}

type AttestationSet struct {
	IDs        []string `json:"ids"`
	MerkleRoot string   `json:"merkle_root"`
}

type Summary struct {
	OutcomeCounts  map[string]int `json:"outcome_counts"`
	SeverityCounts map[string]int `json:"severity_counts"`
}

// event represents an execution event within a flow.
type event struct {
	EventID     string                 `json:"event_id"`
	Action      string                 `json:"action"`
	Status      string                 `json:"status"`
	StartedAt   string                 `json:"started_at"`
	CompletedAt string                 `json:"completed_at"`
	Attributes  map[string]interface{} `json:"attributes"`
}

// policyDoc is the canonical policy as consumed by the verifier.
type policyDoc struct {
	PolicyID          string `json:"policy_id"`
	PolicyVersion     int    `json:"policy_version"`
	TenantID          string `json:"tenant_id"`
	PolicyFingerprint string `json:"policy_fingerprint"`
	Rules             []rule `json:"rules"`
}

type rule struct {
	ID       string                 `json:"id"`
	Category string                 `json:"category"`
	Severity string                 `json:"severity"`
	Spec     map[string]interface{} `json:"spec"`
}

type attestation struct {
	AttestationID string                 `json:"attestation_id"`
	SourceID      string                 `json:"source_id"`
	Claim         string                 `json:"claim"`
	ClaimValue    interface{}            `json:"claim_value"`
	Subject       map[string]interface{} `json:"subject"`
}

const verifierVersion = "1.0.0"
const verifierBuildHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// Verify evaluates a policy against a flow and attestations.
func Verify(flowData []byte, policyData []byte, attestationsData []byte) (*VerificationRun, error) {
	started := nowFunc()

	var flow struct {
		FlowID         string  `json:"flow_id"`
		TenantID       string  `json:"tenant_id"`
		FlowMerkleRoot string  `json:"flow_merkle_root"`
		Events         []event `json:"events"`
	}
	if err := json.Unmarshal(flowData, &flow); err != nil {
		return nil, fmt.Errorf("parse flow: %w", err)
	}

	var policy policyDoc
	if err := json.Unmarshal(policyData, &policy); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if flow.TenantID != "" && policy.TenantID != "" && flow.TenantID != policy.TenantID {
		return nil, fmt.Errorf("tenant mismatch: flow tenant %q does not match policy tenant %q", flow.TenantID, policy.TenantID)
	}

	atts, err := parseAttestations(attestationsData)
	if err != nil {
		return nil, fmt.Errorf("parse attestations: %w", err)
	}

	findings := make([]map[string]interface{}, 0, len(policy.Rules))
	outcomeCounts := map[string]int{"pass": 0, "fail": 0, "inconclusive": 0}
	severityCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

	for _, r := range policy.Rules {
		finding := evaluateRule(r, flow.Events, atts)
		findings = append(findings, finding)
		outcomeCounts[finding["outcome"].(string)]++
		severityCounts[finding["severity"].(string)]++
	}

	status := "pass"
	if outcomeCounts["fail"] > 0 {
		status = "fail"
	} else if outcomeCounts["inconclusive"] > 0 {
		status = "inconclusive"
	}

	attestationIDs := make([]string, 0, len(atts))
	for _, a := range atts {
		attestationIDs = append(attestationIDs, a.AttestationID)
	}

	run := &VerificationRun{
		Schema:            "intentproof.run.v1",
		RunID:             "run_" + flow.FlowID,
		TenantID:          policy.TenantID,
		FlowID:            flow.FlowID,
		FlowMerkleRoot:    flow.FlowMerkleRoot,
		PolicyID:          policy.PolicyID,
		PolicyVersion:     policy.PolicyVersion,
		PolicyFingerprint: policy.PolicyFingerprint,
		VerifierVersion:   verifierVersion,
		VerifierBuildHash: verifierBuildHash,
		AttestationSet: AttestationSet{
			IDs:        attestationIDs,
			MerkleRoot: computeMerkleRoot(attestationIDs),
		},
		StartedAt:  started.Format(time.RFC3339),
		CompletedAt: nowFunc().Format(time.RFC3339),
		Status:     status,
		Summary: Summary{
			OutcomeCounts:  outcomeCounts,
			SeverityCounts: severityCounts,
		},
		Findings: findings,
		Signature: map[string]interface{}{
			"alg":     "ed25519",
			"key_id":  "platform:k1",
			"value":   "",
		},
	}

	fingerprint, err := computeRunFingerprint(run)
	if err != nil {
		return nil, fmt.Errorf("compute run fingerprint: %w", err)
	}
	run.RunFingerprint = fingerprint

	return run, nil
}

func parseAttestations(data []byte) ([]attestation, error) {
	if len(data) == 0 {
		return []attestation{}, nil
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	atts := make([]attestation, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var a attestation
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			return nil, fmt.Errorf("parse attestation line: %w", err)
		}
		atts = append(atts, a)
	}
	return atts, nil
}

func evaluateRule(r rule, events []event, atts []attestation) map[string]interface{} {
	switch r.Category {
	case "required":
		return evaluateRequired(r, events)
	case "forbidden":
		return evaluateForbidden(r, events)
	case "ordering":
		return evaluateOrdering(r, events)
	case "cardinality":
		return evaluateCardinality(r, events)
	case "temporal":
		return evaluateTemporal(r, events)
	case "consensus":
		return evaluateConsensus(r, atts)
	case "value_bound":
		return evaluateValueBound(r, atts)
	case "claim_match":
		return evaluateClaimMatch(r, atts)
	default:
		return finding(r, "inconclusive", fmt.Sprintf("unknown rule category: %s", r.Category), nil)
	}
}

func evaluateRequired(r rule, events []event) map[string]interface{} {
	spec := r.Spec
	action, _ := spec["action"].(string)
	where, _ := spec["where"].(map[string]interface{})

	matched := filterEvents(events, action, where)
	count := len(matched)

	minVal := 0
	if v, ok := spec["min"]; ok {
		minVal = intFromInterface(v)
	}
	maxVal := -1
	if v, ok := spec["max"]; ok {
		maxVal = intFromInterface(v)
	}

	if count < minVal {
		return finding(r, "fail", fmt.Sprintf("required action %q occurred %d time(s), minimum is %d", action, count, minVal), eventIDs(matched))
	}
	if maxVal >= 0 && count > maxVal {
		return finding(r, "fail", fmt.Sprintf("required action %q occurred %d time(s), maximum is %d", action, count, maxVal), eventIDs(matched))
	}
	return finding(r, "pass", fmt.Sprintf("required action %q occurred %d time(s)", action, count), eventIDs(matched))
}

func evaluateForbidden(r rule, events []event) map[string]interface{} {
	spec := r.Spec
	action, _ := spec["action"].(string)
	where, _ := spec["where"].(map[string]interface{})
	after, _ := spec["after"].(string)
	wherePredecessor, _ := spec["where_predecessor"].(map[string]interface{})
	withoutPredecessor, _ := spec["without_predecessor"].(string)

	matched := filterEvents(events, action, where)

	if after != "" {
		predecessors := filterEvents(events, after, wherePredecessor)
		if len(predecessors) > 0 {
			for _, m := range matched {
				mTime := parseEventTime(m.CompletedAt)
				for _, p := range predecessors {
					pTime := parseEventTime(p.CompletedAt)
					if !mTime.IsZero() && !pTime.IsZero() && mTime.After(pTime) {
						return finding(r, "fail", fmt.Sprintf("forbidden action %q occurred after %q", action, after), []string{m.EventID})
					}
				}
			}
		}
		return finding(r, "pass", fmt.Sprintf("forbidden action %q did not occur after %q", action, after), nil)
	}

	if withoutPredecessor != "" {
		predecessors := filterEvents(events, withoutPredecessor, wherePredecessor)
		if len(predecessors) == 0 && len(matched) > 0 {
			return finding(r, "fail", fmt.Sprintf("forbidden action %q occurred without predecessor %q", action, withoutPredecessor), eventIDs(matched))
		}
		// Ensure each matched forbidden event has at least one predecessor BEFORE it.
		var unmatched []event
		for _, m := range matched {
			mTime := parseEventTime(m.CompletedAt)
			hasEarlier := false
			for _, p := range predecessors {
				pTime := parseEventTime(p.CompletedAt)
				if !mTime.IsZero() && !pTime.IsZero() && pTime.Before(mTime) {
					hasEarlier = true
					break
				}
			}
			if !hasEarlier {
				unmatched = append(unmatched, m)
			}
		}
		if len(unmatched) > 0 {
			return finding(r, "fail", fmt.Sprintf("forbidden action %q occurred without earlier predecessor %q", action, withoutPredecessor), eventIDs(unmatched))
		}
		return finding(r, "pass", fmt.Sprintf("forbidden action %q constraint satisfied", action), nil)
	}

	if len(matched) > 0 {
		return finding(r, "fail", fmt.Sprintf("forbidden action %q occurred %d time(s)", action, len(matched)), eventIDs(matched))
	}
	return finding(r, "pass", fmt.Sprintf("forbidden action %q did not occur", action), nil)
}

func evaluateOrdering(r rule, events []event) map[string]interface{} {
	spec := r.Spec
	beforeAction, _ := spec["before"].(string)
	afterAction, _ := spec["after"].(string)

	beforeEvents := filterEvents(events, beforeAction, nil)
	afterEvents := filterEvents(events, afterAction, nil)

	if len(beforeEvents) == 0 {
		return finding(r, "fail", fmt.Sprintf("ordering: before action %q not found", beforeAction), nil)
	}
	if len(afterEvents) == 0 {
		return finding(r, "fail", fmt.Sprintf("ordering: after action %q not found", afterAction), nil)
	}

	beforeTime := earliestCompletion(beforeEvents)
	afterTime := earliestCompletion(afterEvents)

	if !beforeTime.IsZero() && !afterTime.IsZero() && beforeTime.Before(afterTime) {
		return finding(r, "pass", fmt.Sprintf("ordering: %q completed before %q", beforeAction, afterAction), eventIDs(append(beforeEvents, afterEvents...)))
	}
	return finding(r, "fail", fmt.Sprintf("ordering: %q did not complete before %q", beforeAction, afterAction), eventIDs(append(beforeEvents, afterEvents...)))
}

func evaluateCardinality(r rule, events []event) map[string]interface{} {
	spec := r.Spec
	action, _ := spec["action"].(string)
	where, _ := spec["where"].(map[string]interface{})

	matched := filterEvents(events, action, where)
	count := len(matched)

	if exactly, ok := spec["exactly"]; ok {
		exactVal := intFromInterface(exactly)
		if count != exactVal {
			return finding(r, "fail", fmt.Sprintf("cardinality: action %q occurred %d time(s), expected exactly %d", action, count, exactVal), eventIDs(matched))
		}
		return finding(r, "pass", fmt.Sprintf("cardinality: action %q occurred exactly %d time(s)", action, count), eventIDs(matched))
	}

	minVal := 0
	if v, ok := spec["min"]; ok {
		minVal = intFromInterface(v)
	}
	maxVal := -1
	if v, ok := spec["max"]; ok {
		maxVal = intFromInterface(v)
	}

	if count < minVal {
		return finding(r, "fail", fmt.Sprintf("cardinality: action %q occurred %d time(s), minimum is %d", action, count, minVal), eventIDs(matched))
	}
	if maxVal >= 0 && count > maxVal {
		return finding(r, "fail", fmt.Sprintf("cardinality: action %q occurred %d time(s), maximum is %d", action, count, maxVal), eventIDs(matched))
	}
	return finding(r, "pass", fmt.Sprintf("cardinality: action %q occurred %d time(s)", action, count), eventIDs(matched))
}

func evaluateTemporal(r rule, events []event) map[string]interface{} {
	spec := r.Spec
	fromSpec, _ := spec["from"].(map[string]interface{})
	toSpec, _ := spec["to"].(map[string]interface{})
	maxDur, _ := spec["max"].(string)

	fromAction, _ := fromSpec["action"].(string)
	toAction, _ := toSpec["action"].(string)

	fromEvents := filterEvents(events, fromAction, nil)
	toEvents := filterEvents(events, toAction, nil)

	if len(fromEvents) == 0 {
		return finding(r, "fail", fmt.Sprintf("temporal: from action %q not found", fromAction), nil)
	}
	if len(toEvents) == 0 {
		return finding(r, "fail", fmt.Sprintf("temporal: to action %q not found", toAction), nil)
	}

	fromTime := earliestCompletion(fromEvents)
	toTime := earliestCompletion(toEvents)

	if fromTime.IsZero() || toTime.IsZero() {
		return finding(r, "inconclusive", "temporal: unable to determine timestamps", nil)
	}

	duration := toTime.Sub(fromTime)
	if duration < 0 {
		return finding(r, "fail", "temporal: 'to' event occurs before 'from' event", nil)
	}
	maxDuration, err := parseISODuration(maxDur)
	if err != nil {
		return finding(r, "inconclusive", fmt.Sprintf("temporal: invalid max duration %q", maxDur), nil)
	}

	if duration <= maxDuration {
		return finding(r, "pass", fmt.Sprintf("temporal: duration %v within max %v", duration, maxDuration), nil)
	}
	return finding(r, "fail", fmt.Sprintf("temporal: duration %v exceeds max %v", duration, maxDuration), nil)
}

func evaluateConsensus(r rule, atts []attestation) map[string]interface{} {
	spec := r.Spec
	claim, _ := spec["claim"].(string)
	expectedValue := spec["expected_value"]
	sourcesRaw, _ := spec["sources"].([]interface{})
	threshold, _ := spec["threshold"].(map[string]interface{})

	if claim == "" {
		return finding(r, "inconclusive", "consensus: missing claim", nil)
	}

	sources := make([]map[string]interface{}, 0, len(sourcesRaw))
	for _, s := range sourcesRaw {
		if m, ok := s.(map[string]interface{}); ok {
			sources = append(sources, m)
		}
	}

	// Build set of allowed source identifiers from the rule.
	allowedSources := map[string]struct{}{}
	for _, s := range sources {
		if sid, ok := s["source_id"].(string); ok && sid != "" {
			allowedSources[sid] = struct{}{}
		}
		if action, ok := s["action"].(string); ok && action != "" {
			allowedSources[action] = struct{}{}
		}
	}

	matchedAtts := make([]attestation, 0)
	for _, a := range atts {
		if a.Claim != claim {
			continue
		}
		if len(allowedSources) > 0 {
			if _, ok := allowedSources[a.SourceID]; !ok {
				continue
			}
		}
		matchedAtts = append(matchedAtts, a)
	}

	if len(matchedAtts) == 0 {
		return finding(r, "fail", fmt.Sprintf("consensus: no attestations found for claim %q", claim), nil)
	}

	// Count agreements by grouping matched attestations by ClaimValue.
	// When expectedValue is set, count matches against it.
	// When nil, count the largest-value group as the agreeing set.
	agreeCount := 0
	var evidenceIDs []string
	if expectedValue != nil {
		for _, a := range matchedAtts {
			if valuesEqual(a.ClaimValue, expectedValue) {
				agreeCount++
				evidenceIDs = append(evidenceIDs, a.AttestationID)
			}
		}
	} else {
		groups := map[string][]string{}
		for _, a := range matchedAtts {
			key := canonicalClaimValueKey(a.ClaimValue)
			groups[key] = append(groups[key], a.AttestationID)
		}
		keys := make([]string, 0, len(groups))
		for k := range groups {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		maxKey := ""
		maxCount := 0
		for _, k := range keys {
			ids := groups[k]
			if len(ids) > maxCount || (len(ids) == maxCount && (maxKey == "" || k < maxKey)) {
				maxCount = len(ids)
				maxKey = k
			}
		}
		agreeCount = maxCount
		evidenceIDs = groups[maxKey]
	}

	// Validate threshold contains exactly one supported operator.
	if threshold == nil || len(threshold) == 0 {
		return finding(r, "fail", "consensus: threshold is required", nil)
	}
	supported := 0
	for k := range threshold {
		switch k {
		case "unanimous", "majority", "agree_at_least":
			supported++
		default:
			return finding(r, "fail", fmt.Sprintf("consensus: unknown threshold key %q", k), nil)
		}
	}
	if supported != 1 {
		return finding(r, "fail", fmt.Sprintf("consensus: threshold must contain exactly one supported operator, got %d", supported), nil)
	}

	// Evaluate threshold
	thresholdMet := false
	evaluated := false
	if unanimous, ok := threshold["unanimous"].(bool); ok {
		evaluated = true
		if unanimous {
			thresholdMet = agreeCount == len(matchedAtts) && len(matchedAtts) > 0
			if !thresholdMet {
				return finding(r, "fail", fmt.Sprintf("consensus.disagreement: unanimous required, %d/%d agree", agreeCount, len(matchedAtts)), evidenceIDs)
			}
		}
	} else if majority, ok := threshold["majority"].(bool); ok {
		evaluated = true
		if majority {
			thresholdMet = agreeCount > len(matchedAtts)/2
			if !thresholdMet {
				return finding(r, "fail", fmt.Sprintf("consensus.disagreement: majority required, %d/%d agree", agreeCount, len(matchedAtts)), evidenceIDs)
			}
		}
	} else if agreeAtLeast, ok := threshold["agree_at_least"]; ok {
		evaluated = true
		min, err := validateAgreeAtLeast(agreeAtLeast)
		if err != nil {
			return finding(r, "fail", fmt.Sprintf("consensus: invalid agree_at_least: %v", err), nil)
		}
		thresholdMet = agreeCount >= min
		if !thresholdMet {
			return finding(r, "fail", fmt.Sprintf("consensus.disagreement: agree_at_least %d required, %d agree", min, agreeCount), evidenceIDs)
		}
	}

	if !evaluated {
		return finding(r, "fail", fmt.Sprintf("consensus: invalid or unevaluated threshold (keys: %+v)", threshold), nil)
	}
	if !thresholdMet {
		return finding(r, "fail", "consensus: threshold value did not activate the rule", nil)
	}

	return finding(r, "pass", fmt.Sprintf("consensus: %d/%d attestations agree on claim %q", agreeCount, len(matchedAtts), claim), evidenceIDs)
}

func evaluateValueBound(r rule, atts []attestation) map[string]interface{} {
	spec := r.Spec
	claim, _ := spec["claim"].(string)
	operator, _ := spec["operator"].(string)
	sourceID, _ := spec["source_id"].(string)

	if claim == "" || operator == "" {
		return finding(r, "inconclusive", "value_bound: claim and operator are required", nil)
	}

	// Validate operator is supported.
	if !isValidValueBoundOperator(operator) {
		return finding(r, "inconclusive", fmt.Sprintf("value_bound: unsupported operator %q", operator), nil)
	}

	// Validate bound value exists and is numeric.
	boundValue, ok := toFloat64(spec["value"])
	if !ok {
		return finding(r, "inconclusive", "value_bound: spec value must be numeric", nil)
	}

	matched := filterAttestations(atts, claim, sourceID)
	if len(matched) == 0 {
		return finding(r, "fail", fmt.Sprintf("value_bound: no attestations found for claim %q", claim), nil)
	}

	var evidence []string
	failCount := 0
	for _, a := range matched {
		evidence = append(evidence, a.AttestationID)
		num, ok := toFloat64(a.ClaimValue)
		if !ok {
			failCount++
			continue
		}
		if !compareValueBound(num, operator, boundValue) {
			failCount++
		}
	}

	if failCount > 0 {
		return finding(r, "fail", fmt.Sprintf("value_bound: %d/%d attestations violate %s %v for claim %q", failCount, len(matched), operator, boundValue, claim), evidence)
	}
	return finding(r, "pass", fmt.Sprintf("value_bound: all %d attestations satisfy %s %v for claim %q", len(matched), operator, boundValue, claim), evidence)
}

func isValidValueBoundOperator(op string) bool {
	switch op {
	case "lt", "lte", "gt", "gte", "eq", "ne":
		return true
	}
	return false
}

func evaluateClaimMatch(r rule, atts []attestation) map[string]interface{} {
	spec := r.Spec
	claim, _ := spec["claim"].(string)
	expectedValue := spec["expected_value"]
	sourceID, _ := spec["source_id"].(string)

	if claim == "" {
		return finding(r, "inconclusive", "claim_match: claim is required", nil)
	}
	if expectedValue == nil {
		return finding(r, "inconclusive", "claim_match: expected_value is required", nil)
	}

	matched := filterAttestations(atts, claim, sourceID)
	if len(matched) == 0 {
		return finding(r, "fail", fmt.Sprintf("claim_match: no attestations found for claim %q", claim), nil)
	}

	var evidence []string
	failCount := 0
	for _, a := range matched {
		evidence = append(evidence, a.AttestationID)
		if !valuesEqual(a.ClaimValue, expectedValue) {
			failCount++
		}
	}

	if failCount > 0 {
		return finding(r, "fail", fmt.Sprintf("claim_match: %d/%d attestations do not match expected value for claim %q", failCount, len(matched), claim), evidence)
	}
	return finding(r, "pass", fmt.Sprintf("claim_match: all %d attestations match expected value for claim %q", len(matched), claim), evidence)
}

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

// Helpers

func finding(r rule, outcome, reason string, evidence []string) map[string]interface{} {
	if evidence == nil {
		evidence = []string{}
	}
	return map[string]interface{}{
		"rule_id":            r.ID,
		"rule_category":      r.Category,
		"outcome":            outcome,
		"severity":           r.Severity,
		"reason":             reason,
		"evidence_event_ids": evidence,
	}
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
	if len(ids) == 0 {
		return "sha256:" + strings.Repeat("0", 64)
	}
	sort.Strings(ids)

	// Build leaf hashes with length-prefixed encoding to avoid ambiguity.
	leaves := make([][]byte, len(ids))
	for i, id := range ids {
		h := sha256.New()
		lengthPrefix := make([]byte, 8)
		binary.BigEndian.PutUint64(lengthPrefix, uint64(len(id)))
		_, _ = h.Write(lengthPrefix)
		_, _ = h.Write([]byte(id))
		leaves[i] = h.Sum(nil)
	}

	// Iteratively pair and hash until a single root remains.
	level := leaves
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				h := sha256.New()
				_, _ = h.Write(level[i])
				_, _ = h.Write(level[i+1])
				next = append(next, h.Sum(nil))
			} else {
				// Odd number: duplicate the last node.
				h := sha256.New()
				_, _ = h.Write(level[i])
				_, _ = h.Write(level[i])
				next = append(next, h.Sum(nil))
			}
		}
		level = next
	}
	return "sha256:" + hex.EncodeToString(level[0])
}

func computeRunFingerprint(run *VerificationRun) (string, error) {
	// Build a copy excluding fingerprint and signature fields.
	raw, err := json.Marshal(run)
	if err != nil {
		return "", err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", err
	}
	delete(m, "run_fingerprint")
	delete(m, "signature")
	delete(m, "started_at")
	delete(m, "completed_at")

	canonical, err := canonicalJSON(m)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
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
	normalized := normalizeForJSON(v)
	raw, err := json.Marshal(normalized)
	if err != nil {
		return fmt.Sprintf("%T|%v", v, v)
	}
	return string(raw)
}

// canonicalJSON produces deterministic JSON with sorted map keys.
func canonicalJSON(v interface{}) ([]byte, error) {
	normalized := normalizeForJSON(v)
	return json.Marshal(normalized)
}

func normalizeForJSON(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]interface{}, len(x))
		for _, k := range keys {
			out[k] = normalizeForJSON(x[k])
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(x))
		for i, v := range x {
			out[i] = normalizeForJSON(v)
		}
		return out
	default:
		return x
	}
}
