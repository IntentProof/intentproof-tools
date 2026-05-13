package policy

import (
	"fmt"
)

// allowedSeverities is the canonical, ordered set of severity levels
// permitted on a rule. The values mirror the enum in
// spec/schema/policy.v1.schema.json.
var allowedSeverities = []string{"info", "low", "medium", "high", "critical"}

// validateSeverity returns nil when severity is one of the allowed values.
// An empty string is considered invalid here; callers are expected to apply
// a default before calling this helper.
func validateSeverity(severity string) error {
	for _, s := range allowedSeverities {
		if s == severity {
			return nil
		}
	}
	return fmt.Errorf(
		"invalid severity %q: must be one of info, low, medium, high, critical",
		severity,
	)
}

// normalizeMap walks an arbitrary value decoded from YAML and converts any
// map[any]any (yaml.v2 style) keys into map[string]any so the result can be
// safely marshaled as JSON.  Non-string keys are stringified via fmt.Sprint.
// Slices and nested maps are recursed into.  Other scalar values are
// returned as-is.
func normalizeMap(v any) any {
	switch x := v.(type) {
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[fmt.Sprint(k)] = normalizeMap(val)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = normalizeMap(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = normalizeMap(item)
		}
		return out
	default:
		return v
	}
}

// normalizeStringMap is a convenience wrapper that normalizes the value and
// asserts the top-level result is a map[string]any.  It returns nil when the
// input is nil or empty.
func normalizeStringMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out, _ := normalizeMap(in).(map[string]any)
	return out
}
