package domain

import (
	"sort"
	"strings"
	"time"
)

// EvaluatePolicy computes the single deterministic policy conclusion for a
// candidate revision. It is a pure function: the precheck endpoint and the
// formal revision append both call it, so identical inputs always produce
// identical conclusions.
//
// Determinism guarantees:
//   - Enforcement is derived solely from the immutable pinned version
//     (version.Enabled). The mutable package-level toggle never reaches a plan
//     that already pinned a version, so a policy upgrade cannot change its
//     conclusions.
//   - Overlapping rules for the same code are resolved by severity rank
//     (block > warn > ignore) then lexicographic rule ID; every candidate is
//     still reported on the emitted finding.
//   - Expired exceptions never suppress; among active exceptions matching the
//     same code/owner the earliest-expiring one wins, ties broken by ID.
//   - Findings and suppressed entries are emitted in a fixed sorted order, so
//     large entry sets produce identical output regardless of map iteration.
func EvaluatePolicy(
	zone string,
	entries []ZoneEntry,
	pkg PolicyPackage,
	version PolicyPackageVersion,
	now time.Time,
) PolicyVerdict {
	verdict := PolicyVerdict{
		Enabled:     version.Enabled,
		PackageID:   pkg.ID,
		Version:     version.Version,
		EvaluatedAt: now.UTC(),
		Findings:    []PolicyFinding{},
		Suppressed:  []SuppressedFinding{},
	}
	if !verdict.Enabled {
		return verdict
	}

	zone = canonicalName(zone)
	rules := rulesForZone(version.Rules, zone)
	apexRules := overlapWinners(rules, RuleApexCNAME)
	conflictRules := overlapWinners(rules, RuleCNAMEConflict)
	shadowRules := overlapWinners(rules, RuleWildcardShadow)
	exceptions := activeExceptions(version.Exceptions, now)

	// Index entries by owner for the conflict and shadow analyses.
	byOwner := make(map[string][]ZoneEntry)
	var owners []string
	for _, entry := range entries {
		if _, ok := byOwner[entry.Owner]; !ok {
			owners = append(owners, entry.Owner)
		}
		byOwner[entry.Owner] = append(byOwner[entry.Owner], entry)
	}

	type rawFinding struct {
		rule      PolicyRule
		candidate []string
		code      string
		owner     string
		message   string
	}
	var raws []rawFinding
	addRaw := func(won PolicyRule, candidates []PolicyRule, code, owner, message string) {
		ids := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			ids = append(ids, candidate.ID)
		}
		raws = append(raws, rawFinding{
			rule: won, candidate: ids, code: code, owner: owner, message: message,
		})
	}

	// Rule apex_cname: the zone apex must not carry a CNAME record.
	if len(apexRules) > 0 {
		for _, entry := range byOwner[zone] {
			if entry.Type == EntryCNAME {
				addRaw(apexRules[0], apexRules, RuleApexCNAME, zone,
					"zone apex must not carry a CNAME record")
			}
		}
	}

	// Rule cname_conflict: a CNAME owner must not coexist with any other
	// record type, and an owner must carry at most one CNAME value.
	if len(conflictRules) > 0 {
		for _, owner := range owners {
			group := byOwner[owner]
			cnameCount := 0
			otherCount := 0
			for _, entry := range group {
				if entry.Type == EntryCNAME {
					cnameCount++
				} else {
					otherCount++
				}
			}
			if cnameCount > 0 && otherCount > 0 {
				addRaw(conflictRules[0], conflictRules, RuleCNAMEConflict, owner,
					"CNAME owner must not coexist with other record types")
			} else if cnameCount > 1 {
				addRaw(conflictRules[0], conflictRules, RuleCNAMEConflict, owner,
					"owner must not carry multiple CNAME records")
			}
		}
	}

	// Rule wildcard_shadow: a wildcard owner ("*.x.zone") hides every exact
	// owner that lives one label beneath it. Each (wildcard, concrete) pair
	// produces one finding, which keeps the risk explainable entry by entry.
	if len(shadowRules) > 0 {
		sort.Strings(owners)
		var wildcards []string
		for _, owner := range owners {
			if strings.HasPrefix(owner, "*.") {
				wildcards = append(wildcards, owner)
			}
		}
		sort.Strings(wildcards)
		for _, wildcard := range wildcards {
			parent := strings.TrimPrefix(wildcard, "*.")
			prefix := ""
			if parent == "" {
				continue // "*" at the apex is outside the modeled risk
			}
			prefix = "." + parent
			for _, owner := range owners {
				if owner == wildcard || !strings.HasSuffix(owner, prefix) {
					continue
				}
				head := strings.TrimSuffix(owner, prefix)
				if head == "" || strings.Contains(head, ".") {
					continue // only owners exactly one label below are shadowed
				}
				// The finding is attributed to the concrete owner at risk so
				// exceptions can exempt it deterministically; the wildcard
				// responsible is carried in the message.
				addRaw(shadowRules[0], shadowRules, RuleWildcardShadow, owner,
					"exact owner is shadowed by wildcard "+wildcard)
			}
		}
	}

	// Stable ordering for large entry sets: code, then owner, then message.
	sort.Slice(raws, func(i, j int) bool {
		if raws[i].code != raws[j].code {
			return raws[i].code < raws[j].code
		}
		if raws[i].owner != raws[j].owner {
			return raws[i].owner < raws[j].owner
		}
		return raws[i].message < raws[j].message
	})

	allowed := true
	for _, raw := range raws {
		if exception, ok := exceptionFor(exceptions, raw.code, raw.owner); ok {
			verdict.Suppressed = append(verdict.Suppressed, SuppressedFinding{
				Code:        raw.code,
				Owner:       raw.owner,
				RuleID:      raw.rule.ID,
				ExceptionID: exception.ID,
				ExpiresAt:   exception.ExpiresAt.UTC(),
			})
			continue
		}
		verdict.Findings = append(verdict.Findings, PolicyFinding{
			RuleID:           raw.rule.ID,
			Code:             raw.code,
			Severity:         raw.rule.Severity,
			Owner:            raw.owner,
			Message:          raw.message,
			CandidateRuleIDs: raw.candidate,
		})
		if raw.rule.Severity == SeverityBlock {
			allowed = false
		}
	}

	sort.Slice(verdict.Suppressed, func(i, j int) bool {
		if verdict.Suppressed[i].Code != verdict.Suppressed[j].Code {
			return verdict.Suppressed[i].Code < verdict.Suppressed[j].Code
		}
		if verdict.Suppressed[i].Owner != verdict.Suppressed[j].Owner {
			return verdict.Suppressed[i].Owner < verdict.Suppressed[j].Owner
		}
		return verdict.Suppressed[i].ExceptionID < verdict.Suppressed[j].ExceptionID
	})
	verdict.Allowed = allowed
	return verdict
}

// rulesForZone keeps enabled rules whose zone scope covers the zone.
func rulesForZone(rules []PolicyRule, zone string) []PolicyRule {
	result := make([]PolicyRule, 0, len(rules))
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if len(rule.Zones) == 0 {
			result = append(result, rule)
			continue
		}
		for _, scoped := range rule.Zones {
			if canonicalName(scoped) == zone {
				result = append(result, rule)
				break
			}
		}
	}
	return result
}

// overlapWinners returns every enabled rule for a code, ordered by the fixed
// overlap precedence (severity rank, then rule ID). The first element wins;
// the full slice is surfaced on the finding for explainability.
func overlapWinners(rules []PolicyRule, code string) []PolicyRule {
	matches := make([]PolicyRule, 0)
	for _, rule := range rules {
		if rule.Code == code {
			matches = append(matches, rule)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		ri, rj := severityRank(matches[i].Severity), severityRank(matches[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return matches[i].ID < matches[j].ID
	})
	return matches
}

func severityRank(severity PolicySeverity) int {
	switch severity {
	case SeverityBlock:
		return 3
	case SeverityWarn:
		return 2
	case SeverityIgnore:
		return 1
	default:
		return 0
	}
}

func activeExceptions(exceptions []PolicyException, now time.Time) []PolicyException {
	active := make([]PolicyException, 0, len(exceptions))
	for _, exception := range exceptions {
		if exception.ExpiresAt.UTC().After(now.UTC()) {
			active = append(active, exception)
		}
	}
	return active
}

// exceptionFor returns the deterministic winner for a code/owner pair: the
// earliest-expiring active exception, ties broken by exception ID.
func exceptionFor(exceptions []PolicyException, code, owner string) (PolicyException, bool) {
	var winner *PolicyException
	for index := range exceptions {
		exception := exceptions[index]
		if exception.RuleCode != code || canonicalName(exception.Owner) != owner {
			continue
		}
		if winner == nil {
			winner = &exception
			continue
		}
		if exception.ExpiresAt.UTC().Before(winner.ExpiresAt.UTC()) ||
			(exception.ExpiresAt.UTC().Equal(winner.ExpiresAt.UTC()) && exception.ID < winner.ID) {
			winner = &exception
		}
	}
	if winner == nil {
		return PolicyException{}, false
	}
	return *winner, true
}
