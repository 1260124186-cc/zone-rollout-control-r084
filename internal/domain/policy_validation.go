package domain

import (
	"net"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxPolicyNameRunes     = 120
	MaxPolicyRuleIDRunes   = 64
	MaxPolicyReasonRunes   = 256
	MaxPolicyRules         = 100
	MaxPolicyExceptions    = 500
	MinPolicyExceptionLife = 1 * time.Minute
	MaxPolicyExceptionLife = 365 * 24 * time.Hour
)

// supportedRuleCodes is the closed set of business risks the engine evaluates.
var supportedRuleCodes = map[string]struct{}{
	RuleApexCNAME:      {},
	RuleCNAMEConflict:  {},
	RuleWildcardShadow: {},
}

func supportedSeverity(value string) bool {
	switch PolicySeverity(value) {
	case SeverityBlock, SeverityWarn, SeverityIgnore:
		return true
	default:
		return false
	}
}

// NormalizePolicyPackageInput canonicalizes a create-package request.
func NormalizePolicyPackageInput(input PolicyPackageInput) PolicyPackageInput {
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	input.Rules = normalizeRuleInputs(input.Rules)
	input.Exceptions = normalizeExceptionInputs(input.Exceptions)
	return input
}

// NormalizePolicyVersionInput canonicalizes an append-version request.
func NormalizePolicyVersionInput(input PolicyPackageVersionInput) PolicyPackageVersionInput {
	input.Rules = normalizeRuleInputs(input.Rules)
	input.Exceptions = normalizeExceptionInputs(input.Exceptions)
	return input
}

func normalizeRuleInputs(inputs []PolicyRuleInput) []PolicyRuleInput {
	rules := make([]PolicyRuleInput, 0, len(inputs))
	for _, input := range inputs {
		input.ID = strings.TrimSpace(input.ID)
		input.Code = strings.TrimSpace(input.Code)
		input.Severity = strings.ToLower(strings.TrimSpace(input.Severity))
		zones := make([]string, 0, len(input.Zones))
		for _, zone := range input.Zones {
			zones = append(zones, canonicalName(zone))
		}
		sort.Strings(zones)
		input.Zones = zones
		rules = append(rules, input)
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

func normalizeExceptionInputs(inputs []PolicyExceptionInput) []PolicyExceptionInput {
	exceptions := make([]PolicyExceptionInput, 0, len(inputs))
	for _, input := range inputs {
		input.ID = strings.TrimSpace(input.ID)
		input.RuleCode = strings.TrimSpace(input.RuleCode)
		input.Owner = canonicalName(input.Owner)
		input.Reason = strings.TrimSpace(input.Reason)
		if !input.ExpiresAt.IsZero() {
			input.ExpiresAt = input.ExpiresAt.UTC()
		}
		exceptions = append(exceptions, input)
	}
	sort.SliceStable(exceptions, func(i, j int) bool { return exceptions[i].ID < exceptions[j].ID })
	return exceptions
}

// ValidatePolicyRules validates a normalized rule set. Exceptions are checked
// against it so every exception references a rule present in the version.
func ValidatePolicyRules(rules []PolicyRuleInput, exceptions []PolicyExceptionInput, now time.Time) error {
	details := make(map[string]any)
	if len(rules) == 0 {
		details["rules"] = "must contain at least one rule"
	}
	if len(rules) > MaxPolicyRules {
		details["rules"] = "must contain at most 100 rules"
	}
	ruleIDs := make(map[string]struct{}, len(rules))
	ruleCodes := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		field := "rule[" + rule.ID + "]"
		if !validatePolicyID(rule.ID) {
			details[field] = "id may contain only lowercase letters, digits, and hyphens (max 64)"
		}
		if _, duplicate := ruleIDs[rule.ID]; duplicate {
			details[field] = "rule id is duplicated within the version"
		}
		ruleIDs[rule.ID] = struct{}{}
		if _, supported := supportedRuleCodes[rule.Code]; !supported {
			details[field] = "rule code is not supported"
		}
		ruleCodes[rule.Code] = struct{}{}
		if !supportedSeverity(rule.Severity) {
			details[field] = "severity must be block, warn, or ignore"
		}
		for _, zone := range rule.Zones {
			if err := validateCanonicalName(zone); err != nil {
				details[field] = "zone scope is invalid: " + err.Error()
			}
		}
	}
	if len(exceptions) > MaxPolicyExceptions {
		details["exceptions"] = "must contain at most 500 exceptions"
	}
	exceptionIDs := make(map[string]struct{}, len(exceptions))
	for _, exception := range exceptions {
		field := "exception[" + exception.ID + "]"
		if !validatePolicyID(exception.ID) {
			details[field] = "id may contain only lowercase letters, digits, and hyphens (max 64)"
		}
		if _, duplicate := exceptionIDs[exception.ID]; duplicate {
			details[field] = "exception id is duplicated within the version"
		}
		exceptionIDs[exception.ID] = struct{}{}
		if _, supported := supportedRuleCodes[exception.RuleCode]; !supported {
			details[field] = "rule_code is not supported"
		} else if _, hasRule := ruleCodes[exception.RuleCode]; !hasRule {
			details[field] = "rule_code does not reference a rule in this version"
		}
		if err := validateExceptionOwner(exception.Owner); err != nil {
			details[field] = "owner is invalid: " + err.Error()
		}
		if count := utf8.RuneCountInString(exception.Reason); count > MaxPolicyReasonRunes {
			details[field] = "reason must be at most 256 characters"
		}
		if exception.ExpiresAt.IsZero() {
			details[field] = "expires_at is required"
		} else {
			life := exception.ExpiresAt.Sub(now.UTC())
			if life < MinPolicyExceptionLife {
				details[field] = "expires_at must be at least one minute in the future"
			} else if life > MaxPolicyExceptionLife {
				details[field] = "expires_at must be at most 365 days in the future"
			}
		}
	}
	if len(details) > 0 {
		return Validation("policy package is invalid", details)
	}
	return nil
}

func validatePolicyID(value string) bool {
	count := utf8.RuneCountInString(value)
	if count < 3 || count > MaxPolicyRuleIDRunes {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			continue
		}
		return false
	}
	return true
}

// validateExceptionOwner accepts only concrete canonical owner names;
// wildcards cannot be exempted.
func validateExceptionOwner(value string) error {
	if value == "" || strings.HasPrefix(value, "*.") {
		return Validation("must be a concrete owner name", nil)
	}
	return validateCanonicalName(value)
}

// NormalizeRevisionInputDefault keeps the historical behavior: wildcard
// owners are rejected so plans without an enabled policy behave exactly as
// before.
func NormalizeRevisionInputDefault(input RevisionCreateInput) (RevisionCreateInput, error) {
	return normalizeRevisionInput(input, false)
}

// NormalizeRevisionInputForPolicy allows wildcard owner labels ("*.zone"),
// which the wildcard_shadow rule governs. Values still go through the same
// type-specific validation and entries are sorted and deduplicated.
func NormalizeRevisionInputForPolicy(input RevisionCreateInput) (RevisionCreateInput, error) {
	return normalizeRevisionInput(input, true)
}

func normalizeRevisionInput(input RevisionCreateInput, allowWildcard bool) (RevisionCreateInput, error) {
	input.Authority = canonicalName(input.Authority)
	entries := make([]ZoneEntry, 0, len(input.Entries))
	for _, entry := range input.Entries {
		owner := canonicalName(entry.Owner)
		entryType := EntryType(strings.ToUpper(strings.TrimSpace(string(entry.Type))))
		value := strings.TrimSpace(entry.Value)
		switch entryType {
		case EntryA:
			parsed := net.ParseIP(value)
			if parsed == nil || parsed.To4() == nil {
				return RevisionCreateInput{}, Validation("zone entry is invalid", map[string]any{
					"owner": owner,
					"type":  entryType,
					"value": "must be a valid IPv4 address",
				})
			}
			value = parsed.To4().String()
		case EntryAAAA:
			parsed := net.ParseIP(value)
			if parsed == nil || parsed.To4() != nil {
				return RevisionCreateInput{}, Validation("zone entry is invalid", map[string]any{
					"owner": owner,
					"type":  entryType,
					"value": "must be a valid IPv6 address",
				})
			}
			value = parsed.String()
		case EntryCNAME:
			value = canonicalName(value)
			if err := validateCanonicalName(value); err != nil {
				return RevisionCreateInput{}, Validation("zone entry is invalid", map[string]any{
					"owner": owner,
					"type":  entryType,
					"value": err.Error(),
				})
			}
		default:
			return RevisionCreateInput{}, Validation("zone entry is invalid", map[string]any{
				"owner": owner,
				"type":  entry.Type,
				"value": "type must be A, AAAA, or CNAME",
			})
		}
		if allowWildcard {
			if err := validateOwnerName(owner, true); err != nil {
				return RevisionCreateInput{}, Validation("zone entry is invalid", map[string]any{
					"owner": owner,
					"value": err.Error(),
				})
			}
		} else if err := validateCanonicalName(owner); err != nil {
			return RevisionCreateInput{}, Validation("zone entry is invalid", map[string]any{
				"owner": owner,
				"value": err.Error(),
			})
		}
		entries = append(entries, ZoneEntry{Owner: owner, Type: entryType, Value: value})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Owner != entries[j].Owner {
			return entries[i].Owner < entries[j].Owner
		}
		if entries[i].Type != entries[j].Type {
			return entries[i].Type < entries[j].Type
		}
		return entries[i].Value < entries[j].Value
	})
	for index := 1; index < len(entries); index++ {
		if entries[index] == entries[index-1] {
			return RevisionCreateInput{}, Validation("zone entry is duplicated", map[string]any{
				"owner": entries[index].Owner,
				"type":  entries[index].Type,
				"value": entries[index].Value,
			})
		}
	}
	input.Entries = entries
	return input, nil
}

// validateOwnerName validates an owner that may be a wildcard. Only a single
// leading "*." label is accepted; the remainder must be a canonical name.
func validateOwnerName(value string, wildcard bool) error {
	if wildcard && strings.HasPrefix(value, "*.") {
		rest := strings.TrimPrefix(value, "*.")
		if rest == "" {
			return Validation("wildcard owner must name a zone", nil)
		}
		return validateCanonicalName(rest)
	}
	return validateCanonicalName(value)
}
