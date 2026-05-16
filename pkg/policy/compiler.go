package policy

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/intentproof/intentproof-tools/pkg/policysig"
	"gopkg.in/yaml.v3"
)

type RuleCount struct {
	Category string
	Count    int
}

type CompileResult struct {
	Policy      CanonicalPolicy
	Fingerprint string
	RuleCounts  []RuleCount
}

type CanonicalPolicy struct {
	Schema            string          `json:"schema"`
	PolicyID          string          `json:"policy_id"`
	PolicyVersion     int             `json:"policy_version"`
	TenantID          string          `json:"tenant_id"`
	Name              string          `json:"name,omitempty"`
	Description       string          `json:"description,omitempty"`
	SpecVersion       string          `json:"spec_version"`
	Scope             CanonicalScope  `json:"scope"`
	Rules             []CanonicalRule `json:"rules"`
	PolicyFingerprint string          `json:"policy_fingerprint"`
}

type CanonicalScope struct {
	AnyEventActionIn []string `json:"any_event_action_in"`
}

type CanonicalRule struct {
	ID       string         `json:"id"`
	Category string         `json:"category"`
	Severity string         `json:"severity,omitempty"`
	Spec     map[string]any `json:"spec"`
}

type yamlPolicy struct {
	PolicyID      string     `yaml:"policy_id"`
	PolicyVersion int        `yaml:"policy_version"`
	TenantID      string     `yaml:"tenant_id"`
	Name          string     `yaml:"name"`
	Description   string     `yaml:"description"`
	SpecVersion   string     `yaml:"spec_version"`
	Scope         yamlScope  `yaml:"scope"`
	Rules         []yamlRule `yaml:"rules"`
}

type yamlScope struct {
	MatchAction      string   `yaml:"match_action"`
	AnyEventActionIn []string `yaml:"any_event_action_in"`
}

type yamlRule struct {
	ID                 string           `yaml:"id"`
	Type               string           `yaml:"type"`
	Category           string           `yaml:"category"`
	Severity           string           `yaml:"severity"`
	Spec               map[string]any   `yaml:"spec"`
	Action             string           `yaml:"action"`
	Min                any              `yaml:"min"`
	Max                any              `yaml:"max"`
	Exactly            any              `yaml:"exactly"`
	Where              map[string]any   `yaml:"where"`
	After              string           `yaml:"after"`
	Before             string           `yaml:"before"`
	WherePredecessor   map[string]any   `yaml:"where_predecessor"`
	WithoutPredecessor string           `yaml:"without_predecessor"`
	CountBasis         string           `yaml:"count_basis"`
	AllRequiredOK      *bool            `yaml:"all_required_ok"`
	From               map[string]any   `yaml:"from"`
	To                 map[string]any   `yaml:"to"`
	ClockSkewTolerance string           `yaml:"clock_skew_tolerance"`
	Claim              string           `yaml:"claim"`
	ExpectedValue      any              `yaml:"expected_value"`
	RequireSigned      *bool            `yaml:"require_signed_sources"`
	RequireSignedAlias *bool            `yaml:"require_signed"`
	Sources            []map[string]any `yaml:"sources"`
	Threshold          map[string]any   `yaml:"threshold"`
	Operator           string           `yaml:"operator"`
	Value              any              `yaml:"value"`
	SourceID           string           `yaml:"source_id"`
}

func CompileFile(path string) (*CompileResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Compile(raw)
}

func Compile(raw []byte) (*CompileResult, error) {
	var input yamlPolicy
	if err := yaml.Unmarshal(raw, &input); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	if input.PolicyID == "" {
		return nil, errors.New("policy_id is required")
	}
	if input.SpecVersion == "" {
		input.SpecVersion = "1.0.0"
	}
	if input.PolicyVersion <= 0 {
		input.PolicyVersion = 1
	}
	if input.TenantID == "" {
		parts := strings.SplitN(input.PolicyID, ".", 2)
		if len(parts) == 2 && parts[0] != "" {
			input.TenantID = parts[0]
		}
	}
	if input.TenantID == "" {
		return nil, errors.New("tenant_id is required")
	}

	scopeActions := append([]string{}, input.Scope.AnyEventActionIn...)
	if input.Scope.MatchAction != "" {
		scopeActions = append(scopeActions, input.Scope.MatchAction)
	}
	scopeActions = dedupeStrings(scopeActions)
	if len(scopeActions) == 0 {
		return nil, errors.New("scope requires match_action or any_event_action_in")
	}

	rules := make([]CanonicalRule, 0, len(input.Rules))
	ruleCounts := map[string]int{}
	seenRuleIDs := make(map[string]struct{}, len(input.Rules))
	for i, rule := range input.Rules {
		canonical, err := compileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		if _, dup := seenRuleIDs[canonical.ID]; dup {
			return nil, fmt.Errorf("rule %d: duplicate rule id %q", i+1, canonical.ID)
		}
		seenRuleIDs[canonical.ID] = struct{}{}
		rules = append(rules, canonical)
		ruleCounts[canonical.Category]++
	}
	if len(rules) == 0 {
		return nil, errors.New("at least one rule is required")
	}

	policy := CanonicalPolicy{
		Schema:        "intentproof.policy.v1",
		PolicyID:      input.PolicyID,
		PolicyVersion: input.PolicyVersion,
		TenantID:      input.TenantID,
		Name:          input.Name,
		Description:   input.Description,
		SpecVersion:   input.SpecVersion,
		Scope: CanonicalScope{
			AnyEventActionIn: scopeActions,
		},
		Rules: rules,
	}

	fingerprint, err := policysig.ComputeFingerprint(policy)
	if err != nil {
		return nil, err
	}
	policy.PolicyFingerprint = fingerprint

	countPairs := make([]RuleCount, 0, len(ruleCounts))
	for category, count := range ruleCounts {
		countPairs = append(countPairs, RuleCount{Category: category, Count: count})
	}
	sort.Slice(countPairs, func(i, j int) bool {
		return countPairs[i].Category < countPairs[j].Category
	})

	return &CompileResult{
		Policy:      policy,
		Fingerprint: fingerprint,
		RuleCounts:  countPairs,
	}, nil
}

func compileRule(rule yamlRule) (CanonicalRule, error) {
	id := strings.TrimSpace(rule.ID)
	if id == "" {
		return CanonicalRule{}, errors.New("rule id is required")
	}

	category := strings.TrimSpace(rule.Category)
	if category == "" {
		category = strings.TrimSpace(rule.Type)
	}
	if category == "" {
		return CanonicalRule{}, errors.New("rule type or category is required")
	}

	severity := strings.TrimSpace(rule.Severity)
	if severity == "" {
		severity = "medium"
	}
	if err := validateSeverity(severity); err != nil {
		return CanonicalRule{}, err
	}
	if !isKnownRuleCategory(category) {
		return CanonicalRule{}, fmt.Errorf("unknown rule category: %s", category)
	}

	if len(rule.Spec) > 0 {
		return CanonicalRule{
			ID:       id,
			Category: category,
			Severity: severity,
			Spec:     normalizeStringMap(rule.Spec),
		}, nil
	}

	spec := map[string]any{}
	switch category {
	case "required":
		min, err := intFromAny(rule.Min, "min")
		if err != nil {
			return CanonicalRule{}, err
		}
		max, err := intFromAny(rule.Max, "max")
		if err != nil {
			return CanonicalRule{}, err
		}
		if rule.Action == "" {
			return CanonicalRule{}, errors.New("required rule needs action")
		}
		spec["action"] = rule.Action
		if min != nil {
			spec["min"] = *min
		}
		if max != nil {
			spec["max"] = *max
		}
		if err := validateMinMax(min, max); err != nil {
			return CanonicalRule{}, err
		}
		if where := normalizeStringMap(rule.Where); where != nil {
			spec["where"] = where
		}
	case "forbidden":
		if rule.Action == "" {
			return CanonicalRule{}, errors.New("forbidden rule needs action")
		}
		hasWherePred := rule.WherePredecessor != nil
		hasWithoutPred := rule.WithoutPredecessor != ""
		if hasWherePred && hasWithoutPred {
			return CanonicalRule{}, errors.New(
				"forbidden rule cannot set both where_predecessor and without_predecessor",
			)
		}
		if (hasWherePred || hasWithoutPred) && rule.After == "" {
			return CanonicalRule{}, errors.New(
				"forbidden rule with where_predecessor or without_predecessor requires after",
			)
		}
		spec["action"] = rule.Action
		if rule.After != "" {
			spec["after"] = rule.After
		}
		if where := normalizeStringMap(rule.Where); where != nil {
			spec["where"] = where
		}
		if wp := normalizeStringMap(rule.WherePredecessor); wp != nil {
			spec["where_predecessor"] = wp
		}
		if hasWithoutPred {
			spec["without_predecessor"] = rule.WithoutPredecessor
		}
	case "ordering":
		if rule.Before == "" || rule.After == "" {
			return CanonicalRule{}, errors.New("ordering rule needs before and after")
		}
		spec["before"] = rule.Before
		spec["after"] = rule.After
	case "cardinality":
		exactly, err := intFromAny(rule.Exactly, "exactly")
		if err != nil {
			return CanonicalRule{}, err
		}
		min, err := intFromAny(rule.Min, "min")
		if err != nil {
			return CanonicalRule{}, err
		}
		max, err := intFromAny(rule.Max, "max")
		if err != nil {
			return CanonicalRule{}, err
		}
		if rule.Action == "" {
			return CanonicalRule{}, errors.New("cardinality rule needs action")
		}
		if exactly != nil && (min != nil || max != nil) {
			return CanonicalRule{}, errors.New("cardinality exactly conflicts with min/max")
		}
		if err := validateMinMax(min, max); err != nil {
			return CanonicalRule{}, err
		}
		spec["action"] = rule.Action
		if exactly != nil {
			spec["exactly"] = *exactly
		}
		if min != nil {
			spec["min"] = *min
		}
		if max != nil {
			spec["max"] = *max
		}
		if rule.CountBasis != "" {
			spec["count_basis"] = rule.CountBasis
		}
		if where := normalizeStringMap(rule.Where); where != nil {
			spec["where"] = where
		}
	case "temporal":
		if len(rule.From) == 0 || len(rule.To) == 0 {
			return CanonicalRule{}, errors.New("temporal rule needs from and to")
		}
		spec["from"] = normalizeStringMap(rule.From)
		spec["to"] = normalizeStringMap(rule.To)
		if rule.Min != nil {
			if v, ok := rule.Min.(string); ok && v != "" {
				spec["min"] = v
			}
		}
		if rule.Max != nil {
			if v, ok := rule.Max.(string); ok && v != "" {
				spec["max"] = v
			}
		}
		if _, ok := spec["max"]; !ok {
			return CanonicalRule{}, errors.New("temporal rule needs max duration")
		}
		if rule.ClockSkewTolerance != "" {
			spec["clock_skew_tolerance"] = rule.ClockSkewTolerance
		}
	case "consensus":
		if rule.Claim == "" {
			return CanonicalRule{}, errors.New("consensus rule needs claim")
		}
		if len(rule.Sources) == 0 {
			return CanonicalRule{}, errors.New("consensus rule needs sources")
		}
		if len(rule.Threshold) == 0 {
			return CanonicalRule{}, errors.New("consensus rule needs threshold")
		}
		if err := validateThreshold(rule.Threshold); err != nil {
			return CanonicalRule{}, err
		}
		sources := make([]map[string]any, 0, len(rule.Sources))
		for _, source := range rule.Sources {
			normalized := normalizeStringMap(source)
			if normalized == nil {
				normalized = map[string]any{}
			}
			if kind, ok := normalized["kind"].(string); ok {
				if kind == "internal" {
					normalized["kind"] = "intentproof_action"
				}
			}
			sources = append(sources, normalized)
		}
		spec["claim"] = rule.Claim
		spec["sources"] = sources
		spec["threshold"] = normalizeStringMap(rule.Threshold)
		if rule.ExpectedValue != nil {
			spec["expected_value"] = normalizeMap(rule.ExpectedValue)
		}
		if rule.RequireSigned != nil {
			spec["require_signed_sources"] = *rule.RequireSigned
		}
	case "value_bound":
		if rule.Claim == "" {
			return CanonicalRule{}, errors.New("value_bound rule needs claim")
		}
		operator := strings.TrimSpace(rule.Operator)
		if operator == "" {
			return CanonicalRule{}, errors.New("value_bound rule needs operator")
		}
		if !isValueBoundOperator(operator) {
			return CanonicalRule{}, fmt.Errorf(
				"value_bound rule has unsupported operator %q: must be one of lt, lte, gt, gte, eq, ne",
				operator,
			)
		}
		boundValue, ok := numericFromAny(rule.Value)
		if !ok {
			return CanonicalRule{}, errors.New("value_bound rule needs numeric value")
		}
		spec["claim"] = rule.Claim
		spec["operator"] = operator
		spec["value"] = boundValue
		if rule.SourceID != "" {
			spec["source_id"] = rule.SourceID
		}
	case "claim_match":
		if rule.Claim == "" {
			return CanonicalRule{}, errors.New("claim_match rule needs claim")
		}
		if rule.ExpectedValue == nil {
			return CanonicalRule{}, errors.New("claim_match rule needs expected_value")
		}
		spec["claim"] = rule.Claim
		spec["expected_value"] = normalizeMap(rule.ExpectedValue)
		if rule.SourceID != "" {
			spec["source_id"] = rule.SourceID
		}
		if rule.RequireSignedAlias != nil && rule.RequireSigned != nil &&
			*rule.RequireSignedAlias != *rule.RequireSigned {
			return CanonicalRule{}, errors.New(
				"claim_match rule sets conflicting values for " +
					"require_signed and require_signed_sources",
			)
		}
		if rule.RequireSignedAlias != nil {
			spec["require_signed"] = *rule.RequireSignedAlias
		} else if rule.RequireSigned != nil {
			spec["require_signed"] = *rule.RequireSigned
		}
	default:
		return CanonicalRule{}, fmt.Errorf("unknown rule category: %s", category)
	}

	return CanonicalRule{
		ID:       id,
		Category: category,
		Severity: severity,
		Spec:     spec,
	}, nil
}

func isKnownRuleCategory(category string) bool {
	switch category {
	case "required", "forbidden", "ordering", "cardinality", "temporal",
		"consensus", "value_bound", "claim_match":
		return true
	default:
		return false
	}
}

func validateThreshold(threshold map[string]any) error {
	n := 0
	if v, ok := threshold["unanimous"]; ok {
		if b, valid := v.(bool); !valid || !b {
			return errors.New("threshold.unanimous must be true when set")
		}
		n++
	}
	if v, ok := threshold["majority"]; ok {
		if b, valid := v.(bool); !valid || !b {
			return errors.New("threshold.majority must be true when set")
		}
		n++
	}
	if v, ok := threshold["agree_at_least"]; ok {
		switch x := v.(type) {
		case int:
			if x < 1 {
				return errors.New("threshold.agree_at_least must be >= 1")
			}
		case int64:
			if x < 1 {
				return errors.New("threshold.agree_at_least must be >= 1")
			}
		case float64:
			if x < 1 {
				return errors.New("threshold.agree_at_least must be >= 1")
			}
		default:
			return errors.New("threshold.agree_at_least must be numeric")
		}
		n++
	}
	if n != 1 {
		return errors.New("threshold must set exactly one of unanimous, majority, agree_at_least")
	}
	return nil
}

func validateMinMax(min, max *int) error {
	if min != nil && *min < 0 {
		return errors.New("min must be >= 0")
	}
	if max != nil && *max < 0 {
		return errors.New("max must be >= 0")
	}
	if min != nil && max != nil && *min > *max {
		return errors.New("min cannot be greater than max")
	}
	return nil
}

func dedupeStrings(values []string) []string {
	set := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := set[v]; ok {
			continue
		}
		set[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// isValueBoundOperator reports whether op is one of the supported
// comparison operators for a value_bound rule.  The list mirrors the
// enum in spec/schema/policy.v1.schema.json.
func isValueBoundOperator(op string) bool {
	switch op {
	case "lt", "lte", "gt", "gte", "eq", "ne":
		return true
	}
	return false
}

// numericFromAny coerces a YAML-decoded scalar into a float64. It accepts
// int, int64, and float64 inputs; any other type (including strings) yields
// (0, false).
func numericFromAny(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case float64:
		return x, true
	default:
		return 0, false
	}
}

func intFromAny(v any, field string) (*int, error) {
	if v == nil {
		return nil, nil
	}
	switch x := v.(type) {
	case int:
		return &x, nil
	case int64:
		i := int(x)
		return &i, nil
	case float64:
		i := int(x)
		if float64(i) != x {
			return nil, fmt.Errorf("%s must be an integer", field)
		}
		return &i, nil
	default:
		return nil, fmt.Errorf("%s must be an integer", field)
	}
}
