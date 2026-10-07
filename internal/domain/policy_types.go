package domain

import "time"

// PolicySeverity is the severity level a rule assigns to a violation.
type PolicySeverity string

const (
	SeverityBlock  PolicySeverity = "block"
	SeverityWarn   PolicySeverity = "warn"
	SeverityIgnore PolicySeverity = "ignore"
)

// Well-known policy rule codes. They identify the DNS business risks that the
// built-in policy engine understands.
const (
	RuleApexCNAME      = "apex_cname"
	RuleCNAMEConflict  = "cname_conflict"
	RuleWildcardShadow = "wildcard_shadow"
)

// PolicyRule is one rule definition inside an immutable policy version.
type PolicyRule struct {
	ID       string         `json:"id"`
	Code     string         `json:"code"`
	Severity PolicySeverity `json:"severity"`
	// Zones restricts the rule to the listed canonical zone names. An empty
	// list means the rule applies to every governed zone.
	Zones []string `json:"zones,omitempty"`
	// Enabled lets a new version retire a rule without rewriting its ID.
	Enabled bool `json:"enabled"`
}

// PolicyException suppresses findings for a rule on a concrete owner name
// until ExpiresAt. Exceptions are part of the immutable version; expiry is
// evaluated deterministically at evaluation time.
type PolicyException struct {
	ID        string    `json:"id"`
	RuleCode  string    `json:"rule_code"`
	Owner     string    `json:"owner"`
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason,omitempty"`
}

// PolicyPackage is the managed, versioned container of zone policy rules.
type PolicyPackage struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description,omitempty"`
	Version         int       `json:"version"`
	Enabled         bool      `json:"enabled"`
	LatestVersionID string    `json:"latest_version_id,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// PolicyPackageVersion is immutable once written. New package versions never
// rewrite older versions or revisions that pinned them.
type PolicyPackageVersion struct {
	ID         string            `json:"id"`
	PackageID  string            `json:"package_id"`
	Version    int               `json:"version"`
	Enabled    bool              `json:"enabled"`
	Rules      []PolicyRule      `json:"rules"`
	Exceptions []PolicyException `json:"exceptions"`
	CreatedAt  time.Time         `json:"created_at"`
}

// PolicyFinding is one rule violation reported by the engine.
type PolicyFinding struct {
	RuleID   string         `json:"rule_id"`
	Code     string         `json:"code"`
	Severity PolicySeverity `json:"severity"`
	Owner    string         `json:"owner"`
	Message  string         `json:"message"`
	// CandidateRuleIDs lists every enabled matching rule for this code; the
	// first entry won deterministic overlap resolution and produced the
	// finding. This keeps overlap results explainable.
	CandidateRuleIDs []string `json:"candidate_rule_ids,omitempty"`
}

// SuppressedFinding records a finding that an active exception would
// otherwise have raised, so evaluation results stay explainable.
type SuppressedFinding struct {
	Code        string    `json:"code"`
	Owner       string    `json:"owner"`
	RuleID      string    `json:"rule_id"`
	ExceptionID string    `json:"exception_id"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// PolicyVerdict is the single deterministic conclusion produced by both the
// revision precheck and the formal revision append.
type PolicyVerdict struct {
	Enabled   bool   `json:"enabled"`
	Allowed   bool   `json:"allowed"`
	PackageID string `json:"package_id,omitempty"`
	Version   int    `json:"version,omitempty"`
	// EvaluatedAt is the UTC instant used for exception-expiry decisions.
	EvaluatedAt time.Time           `json:"evaluated_at"`
	Findings    []PolicyFinding     `json:"findings"`
	Suppressed  []SuppressedFinding `json:"suppressed,omitempty"`
}

// policy inputs used by the HTTP layer.

type PolicyPackageInput struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Enabled     *bool                  `json:"enabled"`
	Rules       []PolicyRuleInput      `json:"rules"`
	Exceptions  []PolicyExceptionInput `json:"exceptions,omitempty"`
}

type PolicyRuleInput struct {
	ID       string   `json:"id"`
	Code     string   `json:"code"`
	Severity string   `json:"severity"`
	Zones    []string `json:"zones,omitempty"`
	Enabled  *bool    `json:"enabled"`
}

type PolicyExceptionInput struct {
	ID        string    `json:"id"`
	RuleCode  string    `json:"rule_code"`
	Owner     string    `json:"owner"`
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason,omitempty"`
}

type PolicyPackageVersionInput struct {
	Rules      []PolicyRuleInput      `json:"rules"`
	Exceptions []PolicyExceptionInput `json:"exceptions,omitempty"`
	Enabled    *bool                  `json:"enabled"`
}

type PlanPolicyInput struct {
	PackageID string `json:"package_id"`
}
