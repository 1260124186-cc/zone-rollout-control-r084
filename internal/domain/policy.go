package domain

import (
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MinPolicyNameRunes   = 2
	MaxPolicyNameRunes   = 64
	MaxPolicyRules       = 20
	MaxPolicyRuleZones   = 20
	MaxPolicyExceptions  = 50
	MaxPolicyReasonRunes = 200
	// MaxPolicyFindings caps how many findings a conclusion stores. The
	// outcome and counts are always computed over the full finding set, so
	// large entry sets keep a deterministic and explainable result.
	MaxPolicyFindings = 100
)

type PolicyRuleCode string

const (
	RuleApexCNAME      PolicyRuleCode = "apex_cname"
	RuleCNAMEConflict  PolicyRuleCode = "cname_conflict"
	RuleWildcardShadow PolicyRuleCode = "wildcard_shadow"
)

type PolicySeverity string

const (
	SeverityBlock PolicySeverity = "block"
	SeverityWarn  PolicySeverity = "warn"
)

type PolicyOutcome string

const (
	OutcomePass  PolicyOutcome = "pass"
	OutcomeWarn  PolicyOutcome = "warn"
	OutcomeBlock PolicyOutcome = "block"
)

type PolicyRule struct {
	Code     PolicyRuleCode `json:"code"`
	Severity PolicySeverity `json:"severity"`
	Zones    []string       `json:"zones"`
}

type PolicyException struct {
	ID        string         `json:"id"`
	RuleCode  PolicyRuleCode `json:"rule_code"`
	Zone      string         `json:"zone,omitempty"`
	Owner     string         `json:"owner,omitempty"`
	Reason    string         `json:"reason"`
	ExpiresAt time.Time      `json:"expires_at"`
}

// PolicyBundle is an immutable, versioned set of zone policy rules and
// exceptions. Upgrades are published as a new version under the same name
// and never rewrite earlier versions.
type PolicyBundle struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Version    int               `json:"version"`
	Rules      []PolicyRule      `json:"rules"`
	Exceptions []PolicyException `json:"exceptions"`
	CreatedAt  time.Time         `json:"created_at"`
}

type PolicyFinding struct {
	RuleCode    PolicyRuleCode `json:"rule_code"`
	Severity    PolicySeverity `json:"severity"`
	Owner       string         `json:"owner"`
	Type        string         `json:"type"`
	Value       string         `json:"value"`
	Message     string         `json:"message"`
	Suppressed  bool           `json:"suppressed"`
	ExceptionID string         `json:"exception_id,omitempty"`
}

// PolicyConclusion is the deterministic result of evaluating one zone
// revision candidate against one policy bundle version. The same conclusion
// is produced by the precheck endpoint and by the formal revision append.
type PolicyConclusion struct {
	BundleID            string          `json:"bundle_id,omitempty"`
	BundleVersion       int             `json:"bundle_version,omitempty"`
	Outcome             PolicyOutcome   `json:"outcome"`
	Findings            []PolicyFinding `json:"findings"`
	FindingCounts       map[string]int  `json:"finding_counts"`
	RulesEvaluated      int             `json:"rules_evaluated"`
	EntriesEvaluated    int             `json:"entries_evaluated"`
	Truncated           bool            `json:"truncated"`
	SuppressedCount     int             `json:"suppressed_count"`
	ExpiredExceptionIDs []string        `json:"expired_exception_ids,omitempty"`
	EvaluatedAt         time.Time       `json:"evaluated_at"`
}

type PolicyBundleInput struct {
	Name       string                 `json:"name"`
	Rules      []PolicyRuleInput      `json:"rules"`
	Exceptions []PolicyExceptionInput `json:"exceptions"`
}

type PolicyRuleInput struct {
	Code     string   `json:"code"`
	Severity string   `json:"severity"`
	Zones    []string `json:"zones"`
}

type PolicyExceptionInput struct {
	RuleCode  string    `json:"rule_code"`
	Zone      string    `json:"zone"`
	Owner     string    `json:"owner"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
}

func knownPolicyRuleCode(code PolicyRuleCode) bool {
	switch code {
	case RuleApexCNAME, RuleCNAMEConflict, RuleWildcardShadow:
		return true
	}
	return false
}

// NormalizePolicyBundleInput canonicalizes names, zones, and owners and
// sorts rules and exceptions into a stable order so equal inputs always
// produce equal bundles.
func NormalizePolicyBundleInput(input PolicyBundleInput) PolicyBundleInput {
	input.Name = strings.TrimSpace(strings.ToLower(input.Name))
	for index := range input.Rules {
		rule := &input.Rules[index]
		rule.Code = strings.TrimSpace(strings.ToLower(rule.Code))
		rule.Severity = strings.TrimSpace(strings.ToLower(rule.Severity))
		zones := make([]string, 0, len(rule.Zones))
		seen := make(map[string]struct{}, len(rule.Zones))
		for _, zone := range rule.Zones {
			canonical := canonicalName(zone)
			if _, ok := seen[canonical]; ok {
				continue
			}
			seen[canonical] = struct{}{}
			zones = append(zones, canonical)
		}
		sort.Strings(zones)
		rule.Zones = zones
	}
	sort.Slice(input.Rules, func(i, j int) bool {
		if input.Rules[i].Code != input.Rules[j].Code {
			return input.Rules[i].Code < input.Rules[j].Code
		}
		if input.Rules[i].Severity != input.Rules[j].Severity {
			return input.Rules[i].Severity < input.Rules[j].Severity
		}
		return strings.Join(input.Rules[i].Zones, "\x00") < strings.Join(input.Rules[j].Zones, "\x00")
	})
	for index := range input.Exceptions {
		exception := &input.Exceptions[index]
		exception.RuleCode = strings.TrimSpace(strings.ToLower(exception.RuleCode))
		exception.Zone = canonicalName(exception.Zone)
		exception.Owner = canonicalName(exception.Owner)
		exception.Reason = strings.TrimSpace(exception.Reason)
	}
	return input
}

func ValidatePolicyBundleInput(input PolicyBundleInput) error {
	input = NormalizePolicyBundleInput(input)
	details := make(map[string]any)
	if err := validatePolicyName(input.Name); err != nil {
		details["name"] = err.Error()
	}
	if len(input.Rules) < 1 || len(input.Rules) > MaxPolicyRules {
		details["rules"] = "must contain between 1 and 20 items"
	}
	if len(input.Exceptions) > MaxPolicyExceptions {
		details["exceptions"] = "must contain at most 50 items"
	}
	if len(details) > 0 {
		return Validation("policy bundle input is invalid", details)
	}
	for index, rule := range input.Rules {
		if !knownPolicyRuleCode(PolicyRuleCode(rule.Code)) {
			return Validation("policy rule is invalid", map[string]any{
				"index": index,
				"code":  rule.Code,
			})
		}
		if rule.Severity != string(SeverityBlock) && rule.Severity != string(SeverityWarn) {
			return Validation("policy rule is invalid", map[string]any{
				"index":    index,
				"severity": "must be block or warn",
			})
		}
		if len(rule.Zones) > MaxPolicyRuleZones {
			return Validation("policy rule is invalid", map[string]any{
				"index": index,
				"zones": "must contain at most 20 items",
			})
		}
		for _, zone := range rule.Zones {
			if err := validateCanonicalName(zone); err != nil {
				return Validation("policy rule is invalid", map[string]any{
					"index": index,
					"zone":  zone,
					"error": err.Error(),
				})
			}
		}
		if index > 0 {
			previous := input.Rules[index-1]
			if previous.Code == rule.Code && strings.Join(previous.Zones, "\x00") == strings.Join(rule.Zones, "\x00") {
				return Validation("policy rule is duplicated", map[string]any{
					"code":  rule.Code,
					"zones": rule.Zones,
				})
			}
		}
	}
	for index, exception := range input.Exceptions {
		if !knownPolicyRuleCode(PolicyRuleCode(exception.RuleCode)) {
			return Validation("policy exception is invalid", map[string]any{
				"index":     index,
				"rule_code": exception.RuleCode,
			})
		}
		if exception.Zone != "" {
			if err := validateCanonicalName(exception.Zone); err != nil {
				return Validation("policy exception is invalid", map[string]any{
					"index": index,
					"zone":  err.Error(),
				})
			}
		}
		if exception.Owner != "" {
			if err := validateCanonicalName(exception.Owner); err != nil {
				return Validation("policy exception is invalid", map[string]any{
					"index": index,
					"owner": err.Error(),
				})
			}
		}
		if count := utf8.RuneCountInString(exception.Reason); count < 1 || count > MaxPolicyReasonRunes {
			return Validation("policy exception is invalid", map[string]any{
				"index":  index,
				"reason": "must contain between 1 and 200 characters",
			})
		}
		if exception.ExpiresAt.IsZero() {
			return Validation("policy exception is invalid", map[string]any{
				"index":      index,
				"expires_at": "is required",
			})
		}
	}
	return nil
}

func validatePolicyName(value string) error {
	count := utf8.RuneCountInString(value)
	if count < MinPolicyNameRunes || count > MaxPolicyNameRunes {
		return Validation("must contain between 2 and 64 characters", nil)
	}
	for index, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			continue
		}
		if r == '-' && index > 0 {
			continue
		}
		return Validation("may contain only lowercase letters, digits, and hyphens", nil)
	}
	return nil
}

// UnboundPolicyConclusion is the deterministic conclusion for plans that do
// not enable a policy bundle: nothing is evaluated and nothing is blocked.
func UnboundPolicyConclusion(entriesEvaluated int, now time.Time) PolicyConclusion {
	return PolicyConclusion{
		Outcome:          OutcomePass,
		Findings:         []PolicyFinding{},
		FindingCounts:    map[string]int{},
		EntriesEvaluated: entriesEvaluated,
		EvaluatedAt:      now.UTC(),
	}
}

// EvaluatePolicy runs the applicable rules of one immutable bundle version
// against a normalized entry set. It is pure: the same zone, entries, bundle,
// and time always produce the same conclusion, which is what keeps the
// precheck and the formal append in agreement.
func EvaluatePolicy(zone string, entries []ZoneEntry, bundle PolicyBundle, now time.Time) PolicyConclusion {
	now = now.UTC()
	rules := applicableRules(bundle.Rules, zone)
	codes := make([]PolicyRuleCode, 0, len(rules))
	for code := range rules {
		codes = append(codes, code)
	}
	sort.Slice(codes, func(i, j int) bool { return codes[i] < codes[j] })

	findings := make([]PolicyFinding, 0)
	for _, code := range codes {
		severity := rules[code]
		for _, hit := range detectPolicyHits(code, zone, entries) {
			findings = append(findings, PolicyFinding{
				RuleCode: code,
				Severity: severity,
				Owner:    hit.owner,
				Type:     hit.entryType,
				Value:    hit.value,
				Message:  hit.message,
			})
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].RuleCode != findings[j].RuleCode {
			return findings[i].RuleCode < findings[j].RuleCode
		}
		if findings[i].Owner != findings[j].Owner {
			return findings[i].Owner < findings[j].Owner
		}
		if findings[i].Type != findings[j].Type {
			return findings[i].Type < findings[j].Type
		}
		return findings[i].Value < findings[j].Value
	})

	conclusion := PolicyConclusion{
		BundleID:         bundle.ID,
		BundleVersion:    bundle.Version,
		Outcome:          OutcomePass,
		FindingCounts:    map[string]int{},
		RulesEvaluated:   len(codes),
		EntriesEvaluated: len(entries),
		EvaluatedAt:      now,
	}
	expired := make(map[string]struct{})
	for index := range findings {
		finding := &findings[index]
		active, matchedExpired := matchPolicyException(bundle.Exceptions, *finding, zone, now)
		switch {
		case active != nil:
			finding.Suppressed = true
			finding.ExceptionID = active.ID
			conclusion.SuppressedCount++
		default:
			if matchedExpired != nil {
				expired[matchedExpired.ID] = struct{}{}
			}
			conclusion.FindingCounts[string(finding.RuleCode)]++
			if finding.Severity == SeverityBlock {
				conclusion.Outcome = OutcomeBlock
			} else if conclusion.Outcome == OutcomePass {
				conclusion.Outcome = OutcomeWarn
			}
		}
	}
	if len(expired) > 0 {
		ids := make([]string, 0, len(expired))
		for id := range expired {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		conclusion.ExpiredExceptionIDs = ids
	}
	if len(findings) > MaxPolicyFindings {
		conclusion.Truncated = true
		findings = findings[:MaxPolicyFindings]
	}
	conclusion.Findings = findings
	return conclusion
}

// applicableRules resolves rule overlap deterministically: rules that share
// a code and both apply to the zone collapse into one effective rule whose
// severity is the strictest (block beats warn).
func applicableRules(rules []PolicyRule, zone string) map[PolicyRuleCode]PolicySeverity {
	effective := make(map[PolicyRuleCode]PolicySeverity)
	for _, rule := range rules {
		if len(rule.Zones) > 0 && !containsString(rule.Zones, zone) {
			continue
		}
		current, ok := effective[rule.Code]
		if !ok || rule.Severity == SeverityBlock {
			current = rule.Severity
		}
		effective[rule.Code] = current
	}
	return effective
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// matchPolicyException finds the first active exception covering a finding.
// Exceptions are scanned in bundle order, so the result is deterministic.
// An exception that matches but is expired does not suppress; it is returned
// separately so the conclusion can explain why it was ignored.
func matchPolicyException(
	exceptions []PolicyException,
	finding PolicyFinding,
	zone string,
	now time.Time,
) (*PolicyException, *PolicyException) {
	var expired *PolicyException
	for index := range exceptions {
		exception := &exceptions[index]
		if exception.RuleCode != finding.RuleCode {
			continue
		}
		if exception.Zone != "" && exception.Zone != zone {
			continue
		}
		if exception.Owner != "" && exception.Owner != finding.Owner {
			continue
		}
		if now.Before(exception.ExpiresAt.UTC()) {
			return exception, nil
		}
		if expired == nil {
			expired = exception
		}
	}
	return nil, expired
}

type policyHit struct {
	owner     string
	entryType string
	value     string
	message   string
}

func detectPolicyHits(code PolicyRuleCode, zone string, entries []ZoneEntry) []policyHit {
	switch code {
	case RuleApexCNAME:
		return detectApexCNAME(zone, entries)
	case RuleCNAMEConflict:
		return detectCNAMEConflict(entries)
	case RuleWildcardShadow:
		return detectWildcardShadow(entries)
	}
	return nil
}

func detectApexCNAME(zone string, entries []ZoneEntry) []policyHit {
	hits := make([]policyHit, 0)
	for _, entry := range entries {
		if entry.Type == EntryCNAME && entry.Owner == zone {
			hits = append(hits, policyHit{
				owner:     entry.Owner,
				entryType: string(entry.Type),
				value:     entry.Value,
				message:   "cname record is not allowed at the zone apex",
			})
		}
	}
	return hits
}

func detectCNAMEConflict(entries []ZoneEntry) []policyHit {
	counts := make(map[string]int)
	firstCNAME := make(map[string]string)
	for _, entry := range entries {
		counts[entry.Owner]++
		if entry.Type == EntryCNAME {
			if _, ok := firstCNAME[entry.Owner]; !ok {
				firstCNAME[entry.Owner] = entry.Value
			}
		}
	}
	owners := make([]string, 0, len(firstCNAME))
	for owner := range firstCNAME {
		owners = append(owners, owner)
	}
	sort.Strings(owners)
	hits := make([]policyHit, 0)
	for _, owner := range owners {
		if counts[owner] < 2 {
			continue
		}
		hits = append(hits, policyHit{
			owner:     owner,
			entryType: string(EntryCNAME),
			value:     firstCNAME[owner],
			message:   "cname record coexists with other records at the same owner",
		})
	}
	return hits
}

func detectWildcardShadow(entries []ZoneEntry) []policyHit {
	type wildcard struct {
		owner  string
		suffix string
		entry  ZoneEntry
	}
	wildcards := make([]wildcard, 0)
	explicitOwners := make(map[string]struct{})
	for _, entry := range entries {
		if strings.HasPrefix(entry.Owner, "*.") {
			wildcards = append(wildcards, wildcard{
				owner:  entry.Owner,
				suffix: strings.TrimPrefix(entry.Owner, "*."),
				entry:  entry,
			})
			continue
		}
		explicitOwners[entry.Owner] = struct{}{}
	}
	if len(wildcards) == 0 {
		return nil
	}
	owners := make([]string, 0, len(explicitOwners))
	for owner := range explicitOwners {
		owners = append(owners, owner)
	}
	sort.Strings(owners)
	hits := make([]policyHit, 0)
	for _, wild := range wildcards {
		for _, owner := range owners {
			if !strings.HasSuffix(owner, "."+wild.suffix) {
				continue
			}
			hits = append(hits, policyHit{
				owner:     owner,
				entryType: string(wild.entry.Type),
				value:     wild.owner,
				message:   "explicit record is not covered by wildcard " + wild.owner,
			})
		}
	}
	return hits
}
