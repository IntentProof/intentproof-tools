package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// DiffChangeKind classifies a single semantic change.
type DiffChangeKind string

const (
	ChangeKindAdded   DiffChangeKind = "added"
	ChangeKindRemoved DiffChangeKind = "removed"
	ChangeKindChanged DiffChangeKind = "changed"
)

// RuleDiff captures semantic changes for a single rule.
type RuleDiff struct {
	RuleID      string         `json:"rule_id"`
	Kind        DiffChangeKind `json:"kind"`
	OldCategory string         `json:"old_category,omitempty"`
	NewCategory string         `json:"new_category,omitempty"`
	OldSeverity string         `json:"old_severity,omitempty"`
	NewSeverity string         `json:"new_severity,omitempty"`
	SpecChanges []SpecChange   `json:"spec_changes,omitempty"`
}

// SpecChange reports a change within a rule's spec map.
type SpecChange struct {
	Kind     DiffChangeKind `json:"kind"`
	Key      string         `json:"key"`
	OldValue any            `json:"old_value,omitempty"`
	NewValue any            `json:"new_value,omitempty"`
}

// PolicyDiff captures top-level metadata changes.
type PolicyDiff struct {
	Kind     DiffChangeKind `json:"kind"`
	Field    string         `json:"field"`
	OldValue any            `json:"old_value,omitempty"`
	NewValue any            `json:"new_value,omitempty"`
}

// DiffResult is the stable, deterministic semantic diff between two policies.
type DiffResult struct {
	Same            bool         `json:"same"`
	PolicyChanges   []PolicyDiff `json:"policy_changes,omitempty"`
	RuleChanges     []RuleDiff   `json:"rule_changes,omitempty"`
	OldFingerprint  string       `json:"old_fingerprint"`
	NewFingerprint  string       `json:"new_fingerprint"`
}

// Diff computes a deterministic semantic diff between two compiled policies.
func Diff(left, right *CompileResult) *DiffResult {
	l := left
	if l == nil {
		l = &CompileResult{}
	}
	r := right
	if r == nil {
		r = &CompileResult{}
	}

	result := &DiffResult{
		Same:           true,
		OldFingerprint: l.Fingerprint,
		NewFingerprint: r.Fingerprint,
	}

	result.PolicyChanges = diffPolicyMetadata(&l.Policy, &r.Policy)
	result.RuleChanges = diffRules(l.Policy.Rules, r.Policy.Rules)

	if len(result.PolicyChanges) > 0 || len(result.RuleChanges) > 0 {
		result.Same = false
	}

	// Ensure stable ordering for deterministic output.
	sort.Slice(result.PolicyChanges, func(i, j int) bool {
		if result.PolicyChanges[i].Field != result.PolicyChanges[j].Field {
			return result.PolicyChanges[i].Field < result.PolicyChanges[j].Field
		}
		return result.PolicyChanges[i].Kind < result.PolicyChanges[j].Kind
	})
	sort.Slice(result.RuleChanges, func(i, j int) bool {
		return result.RuleChanges[i].RuleID < result.RuleChanges[j].RuleID
	})
	for i := range result.RuleChanges {
		sort.Slice(result.RuleChanges[i].SpecChanges, func(a, b int) bool {
			if result.RuleChanges[i].SpecChanges[a].Key != result.RuleChanges[i].SpecChanges[b].Key {
				return result.RuleChanges[i].SpecChanges[a].Key < result.RuleChanges[i].SpecChanges[b].Key
			}
			return result.RuleChanges[i].SpecChanges[a].Kind < result.RuleChanges[i].SpecChanges[b].Kind
		})
	}

	return result
}

func diffPolicyMetadata(left, right *CanonicalPolicy) []PolicyDiff {
	var changes []PolicyDiff

	changes = appendIfDifferent(changes, "name", left.Name, right.Name)
	changes = appendIfDifferent(changes, "description", left.Description, right.Description)
	changes = appendIfDifferent(changes, "spec_version", left.SpecVersion, right.SpecVersion)
	changes = appendIfDifferent(changes, "policy_version", left.PolicyVersion, right.PolicyVersion)
	changes = appendIfDifferent(changes, "policy_id", left.PolicyID, right.PolicyID)
	changes = appendIfDifferent(changes, "tenant_id", left.TenantID, right.TenantID)

	leftScope := canonicalizeScope(left.Scope)
	rightScope := canonicalizeScope(right.Scope)
	if !deepJSONEqual(leftScope, rightScope) {
		changes = append(changes, PolicyDiff{
			Kind:     ChangeKindChanged,
			Field:    "scope",
			OldValue: leftScope,
			NewValue: rightScope,
		})
	}

	return changes
}

func canonicalizeScope(s CanonicalScope) any {
	actions := make([]string, len(s.AnyEventActionIn))
	copy(actions, s.AnyEventActionIn)
	sort.Strings(actions)
	return map[string]any{"any_event_action_in": actions}
}

func appendIfDifferent(changes []PolicyDiff, field string, oldVal, newVal any) []PolicyDiff {
	if !deepJSONEqual(oldVal, newVal) {
		changes = append(changes, PolicyDiff{
			Kind:     ChangeKindChanged,
			Field:    field,
			OldValue: oldVal,
			NewValue: newVal,
		})
	}
	return changes
}

func diffRules(left, right []CanonicalRule) []RuleDiff {
	leftByID := indexRules(left)
	rightByID := indexRules(right)

	allIDs := make(map[string]struct{})
	for id := range leftByID {
		allIDs[id] = struct{}{}
	}
	for id := range rightByID {
		allIDs[id] = struct{}{}
	}

	ids := make([]string, 0, len(allIDs))
	for id := range allIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var changes []RuleDiff
	for _, id := range ids {
		l, lok := leftByID[id]
		r, rok := rightByID[id]
		if lok && !rok {
			changes = append(changes, RuleDiff{
				RuleID:      id,
				Kind:        ChangeKindRemoved,
				OldCategory: l.Category,
				OldSeverity: l.Severity,
			})
			continue
		}
		if !lok && rok {
			changes = append(changes, RuleDiff{
				RuleID:      id,
				Kind:        ChangeKindAdded,
				NewCategory: r.Category,
				NewSeverity: r.Severity,
			})
			continue
		}

		rd := diffOneRule(l, r)
		if rd != nil {
			changes = append(changes, *rd)
		}
	}

	return changes
}

func indexRules(rules []CanonicalRule) map[string]CanonicalRule {
	m := make(map[string]CanonicalRule, len(rules))
	for _, r := range rules {
		m[r.ID] = r
	}
	return m
}

func diffOneRule(left, right CanonicalRule) *RuleDiff {
	var changes []SpecChange

	if left.Category != right.Category {
		changes = append(changes, SpecChange{
			Kind:     ChangeKindChanged,
			Key:      "category",
			OldValue: left.Category,
			NewValue: right.Category,
		})
	}
	if left.Severity != right.Severity {
		changes = append(changes, SpecChange{
			Kind:     ChangeKindChanged,
			Key:      "severity",
			OldValue: left.Severity,
			NewValue: right.Severity,
		})
	}

	// Diff spec keys.
	allKeys := make(map[string]struct{})
	for k := range left.Spec {
		allKeys[k] = struct{}{}
	}
	for k := range right.Spec {
		allKeys[k] = struct{}{}
	}
	keys := make([]string, 0, len(allKeys))
	for k := range allKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		lv, lok := left.Spec[k]
		rv, rok := right.Spec[k]
		if lok && !rok {
			changes = append(changes, SpecChange{
				Kind:     ChangeKindRemoved,
				Key:      k,
				OldValue: lv,
			})
			continue
		}
		if !lok && rok {
			changes = append(changes, SpecChange{
				Kind:     ChangeKindAdded,
				Key:      k,
				NewValue: rv,
			})
			continue
		}
		if !deepJSONEqual(lv, rv) {
			changes = append(changes, SpecChange{
				Kind:     ChangeKindChanged,
				Key:      k,
				OldValue: lv,
				NewValue: rv,
			})
		}
	}

	if len(changes) == 0 {
		return nil
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Key != changes[j].Key {
			return changes[i].Key < changes[j].Key
		}
		return changes[i].Kind < changes[j].Kind
	})

	return &RuleDiff{
		RuleID:      left.ID,
		Kind:        ChangeKindChanged,
		OldCategory: left.Category,
		NewCategory: right.Category,
		OldSeverity: left.Severity,
		NewSeverity: right.Severity,
		SpecChanges: changes,
	}
}

func deepJSONEqual(a, b any) bool {
	ja, err := json.Marshal(a)
	if err != nil {
		// fallback to string comparison for non-JSON-able values
		return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
	}
	jb, err := json.Marshal(b)
	if err != nil {
		return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
	}
	return bytes.Equal(ja, jb)
}

// FormatDiff returns a human-readable, deterministic representation of the diff.
func FormatDiff(result *DiffResult) string {
	if result.Same {
		return "policies are semantically identical\n"
	}

	var sb strings.Builder

	if len(result.PolicyChanges) > 0 {
		sb.WriteString("policy metadata changes:\n")
		for _, c := range result.PolicyChanges {
			switch c.Kind {
			case ChangeKindChanged:
				fmt.Fprintf(&sb, "  ~ %s: %v -> %v\n", c.Field, c.OldValue, c.NewValue)
			}
		}
	}

	if len(result.RuleChanges) > 0 {
		sb.WriteString("rule changes:\n")
		for _, r := range result.RuleChanges {
			switch r.Kind {
			case ChangeKindAdded:
				fmt.Fprintf(&sb, "  + %s (%s, %s)\n", r.RuleID, r.NewCategory, r.NewSeverity)
			case ChangeKindRemoved:
				fmt.Fprintf(&sb, "  - %s (%s, %s)\n", r.RuleID, r.OldCategory, r.OldSeverity)
			case ChangeKindChanged:
				fmt.Fprintf(&sb, "  ~ %s\n", r.RuleID)
				for _, sc := range r.SpecChanges {
					switch sc.Kind {
					case ChangeKindAdded:
						fmt.Fprintf(&sb, "      + %s: %v\n", sc.Key, sc.NewValue)
					case ChangeKindRemoved:
						fmt.Fprintf(&sb, "      - %s: %v\n", sc.Key, sc.OldValue)
					case ChangeKindChanged:
						fmt.Fprintf(&sb, "      ~ %s: %v -> %v\n", sc.Key, sc.OldValue, sc.NewValue)
					}
				}
			}
		}
	}

	fmt.Fprintf(&sb, "old fingerprint: %s\n", result.OldFingerprint)
	fmt.Fprintf(&sb, "new fingerprint: %s\n", result.NewFingerprint)

	return sb.String()
}
