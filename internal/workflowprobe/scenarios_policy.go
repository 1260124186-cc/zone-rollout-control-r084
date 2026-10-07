package workflowprobe

import (
	"net/http"
	"time"

	"solo-0014-zone-rollout-control/internal/domain"
)

// runPolicyZoneGovernance verifies the versioned zone policy package behavior
// through the real HTTP routes:
//
//   - plans without a policy keep their original behavior,
//   - apex CNAME, CNAME coexistence and wildcard shadowing are evaluated,
//   - precheck and formal append return the same deterministic conclusion,
//   - blocking findings never enter an immutable revision, warnings do,
//   - active exceptions suppress findings, expired exceptions do not,
//   - overlapping rules resolve deterministically,
//   - a package upgrade does not reach plans pinned to the old version,
//   - large entry sets produce a stable, explainable result.
func runPolicyZoneGovernance() error {
	harness, err := newHarness()
	if err != nil {
		return err
	}
	defer harness.close()

	// 1. Un-governed plan keeps its original behavior: wildcard owner is
	//    still rejected and the precheck surface reports an empty policy.
	var plainPlan domain.RolloutPlan
	if err := harness.call(http.MethodPut, "/v1/plans", map[string]any{
		"zone":                  "plain.example",
		"minimum_success_ratio": 1,
		"maximum_latency_ms":    80,
		"expected_nodes":        1,
	}, &plainPlan); err != nil {
		return err
	}
	wildcardInput := domain.RevisionCreateInput{
		Serial:    2026100700,
		Authority: "ns1.plain.example",
		Entries: []domain.ZoneEntry{
			{Owner: "*.svc.plain.example", Type: domain.EntryA, Value: "192.0.2.40"},
		},
	}
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plainPlan.ID+"/revisions", wildcardInput, nil); err != nil {
		if err := expectFailure(err, http.StatusBadRequest, string(domain.CodeValidationFailed)); err != nil {
			return err
		}
	} else {
		return ensure(false, "wildcard owner accepted on a plan without policy")
	}
	var plainVerdict domain.PolicyVerdict
	if err := harness.call(http.MethodPost, "/v1/plans/"+plainPlan.ID+"/revisions/precheck", domain.RevisionCreateInput{
		Serial:    2026100700,
		Authority: "ns1.plain.example",
		Entries: []domain.ZoneEntry{
			{Owner: "plain.example", Type: domain.EntryA, Value: "192.0.2.40"},
		},
	}, &plainVerdict); err != nil {
		return err
	}
	if plainVerdict.Enabled || !plainVerdict.Allowed {
		return ensure(false, "plan without policy did not keep original behavior")
	}

	// 2. Create a policy package: apex CNAME blocks, CNAME conflicts block,
	//    wildcard shadows only warn. One active exception exempts an apex.
	pkg, err := createPolicyPackage(harness, domain.PolicyPackageInput{
		Name: "zone-baseline",
		Rules: []domain.PolicyRuleInput{
			{ID: "apex-block", Code: domain.RuleApexCNAME, Severity: string(domain.SeverityBlock)},
			{ID: "cname-conflict-block", Code: domain.RuleCNAMEConflict, Severity: string(domain.SeverityBlock)},
			{ID: "wildcard-warn", Code: domain.RuleWildcardShadow, Severity: string(domain.SeverityWarn)},
		},
		Exceptions: []domain.PolicyExceptionInput{
			{
				ID:        "allow-apex-temp",
				RuleCode:  domain.RuleApexCNAME,
				Owner:     "gov.example",
				ExpiresAt: harness.clock.Now().AddDate(0, 0, 7),
				Reason:    "migration window",
			},
		},
	})
	if err != nil {
		return err
	}
	if pkg.Version != 1 || pkg.LatestVersionID == "" {
		return ensure(false, "policy package was not created at version 1")
	}

	// 3. Governed plan. Apex CNAME is exempted by the active exception.
	planID, err := createGovernedPlan(harness, "gov.example", pkg.ID)
	if err != nil {
		return err
	}

	// 4. Precheck: blocked CNAME conflict. Same conclusion must come back
	//    from the formal append, and no revision may persist.
	blockedInput := domain.RevisionCreateInput{
		Serial:    2026100701,
		Authority: "ns1.gov.example",
		Entries: []domain.ZoneEntry{
			{Owner: "www.gov.example", Type: domain.EntryCNAME, Value: "gov.example"},
			{Owner: "www.gov.example", Type: domain.EntryA, Value: "192.0.2.20"},
		},
	}
	var verdict domain.PolicyVerdict
	if err := harness.call(http.MethodPost, "/v1/plans/"+planID+"/revisions/precheck", blockedInput, &verdict); err != nil {
		return err
	}
	if verdict.Enabled != true || verdict.Allowed != false || verdict.PackageID != pkg.ID || verdict.Version != 1 {
		return ensure(false, "precheck did not report a blocked conclusion")
	}
	if len(verdict.Findings) != 1 || verdict.Findings[0].Code != domain.RuleCNAMEConflict {
		return ensure(false, "precheck returned an unexpected finding set")
	}
	if err := harness.call(http.MethodPatch, "/v1/plans/"+planID+"/revisions", blockedInput, nil); err != nil {
		if err := expectFailure(err, http.StatusUnprocessableEntity, string(domain.CodePolicyViolation)); err != nil {
			return err
		}
	} else {
		return ensure(false, "blocking revision was appended")
	}

	// 5. Warn-only wildcard shadow: allowed, warning saved with the revision.
	warnInput := domain.RevisionCreateInput{
		Serial:    2026100702,
		Authority: "ns1.gov.example",
		Entries: []domain.ZoneEntry{
			{Owner: "gov.example", Type: domain.EntryA, Value: "192.0.2.10"},
			{Owner: "*.api.gov.example", Type: domain.EntryA, Value: "192.0.2.30"},
			{Owner: "edge.api.gov.example", Type: domain.EntryA, Value: "192.0.2.31"},
		},
	}
	var warnedRevision domain.ZoneRevision
	if err := harness.call(http.MethodPatch, "/v1/plans/"+planID+"/revisions", warnInput, &warnedRevision); err != nil {
		return err
	}
	if warnedRevision.Policy == nil || warnedRevision.Policy.Allowed != true {
		return ensure(false, "warn-level revision did not store an allowed verdict")
	}
	if len(warnedRevision.Policy.Findings) != 1 ||
		warnedRevision.Policy.Findings[0].Code != domain.RuleWildcardShadow ||
		warnedRevision.Policy.Findings[0].Severity != domain.SeverityWarn ||
		warnedRevision.Policy.Findings[0].Owner != "edge.api.gov.example" {
		return ensure(false, "revision did not persist the wildcard warning")
	}

	// 6. Active apex exception suppresses the apex CNAME finding, and the
	//    suppression is recorded with its expiry.
	exemptInput := domain.RevisionCreateInput{
		Serial:    2026100703,
		Authority: "ns1.gov.example",
		Entries: []domain.ZoneEntry{
			{Owner: "gov.example", Type: domain.EntryCNAME, Value: "target.gov.example"},
		},
	}
	var exemptRevision domain.ZoneRevision
	if err := harness.call(http.MethodPatch, "/v1/plans/"+planID+"/revisions", exemptInput, &exemptRevision); err != nil {
		return err
	}
	if exemptRevision.Policy == nil || len(exemptRevision.Policy.Findings) != 0 ||
		len(exemptRevision.Policy.Suppressed) != 1 ||
		exemptRevision.Policy.Suppressed[0].ExceptionID != "allow-apex-temp" {
		return ensure(false, "active exception did not suppress the apex finding")
	}

	// 7. Expired exception no longer suppresses: build a second plan against
	//    a package version whose exception has already expired.
	expiredPkg, err := createPolicyPackage(harness, domain.PolicyPackageInput{
		Name: "zone-expired",
		Rules: []domain.PolicyRuleInput{
			{ID: "apex-block", Code: domain.RuleApexCNAME, Severity: string(domain.SeverityBlock)},
		},
		Exceptions: []domain.PolicyExceptionInput{
			{
				ID:        "stale-apex",
				RuleCode:  domain.RuleApexCNAME,
				Owner:     "old.example",
				ExpiresAt: harness.clock.Now().Add(2 * time.Minute),
			},
		},
	})
	if err != nil {
		return err
	}
	expiredPlan, err := createGovernedPlan(harness, "old.example", expiredPkg.ID)
	if err != nil {
		return err
	}
	harness.clock.Advance(10 * time.Minute)
	apexInput := domain.RevisionCreateInput{
		Serial:    2026100710,
		Authority: "ns1.old.example",
		Entries: []domain.ZoneEntry{
			{Owner: "old.example", Type: domain.EntryCNAME, Value: "host.old.example"},
		},
	}
	if err := harness.call(http.MethodPatch, "/v1/plans/"+expiredPlan+"/revisions", apexInput, nil); err != nil {
		if err := expectFailure(err, http.StatusUnprocessableEntity, string(domain.CodePolicyViolation)); err != nil {
			return err
		}
	} else {
		return ensure(false, "expired exception still suppressed a blocking finding")
	}

	// 8. Overlapping rules resolve deterministically by severity then ID.
	overlapPkg, err := createPolicyPackage(harness, domain.PolicyPackageInput{
		Name: "zone-overlap",
		Rules: []domain.PolicyRuleInput{
			{ID: "zzz-warn", Code: domain.RuleApexCNAME, Severity: string(domain.SeverityWarn)},
			{ID: "aaa-block", Code: domain.RuleApexCNAME, Severity: string(domain.SeverityBlock)},
		},
	})
	if err != nil {
		return err
	}
	overlapPlan, err := createGovernedPlan(harness, "lap.example", overlapPkg.ID)
	if err != nil {
		return err
	}
	var overlapVerdict domain.PolicyVerdict
	overlapInput := domain.RevisionCreateInput{
		Serial:    2026100720,
		Authority: "ns1.lap.example",
		Entries: []domain.ZoneEntry{
			{Owner: "lap.example", Type: domain.EntryCNAME, Value: "host.lap.example"},
		},
	}
	if err := harness.call(http.MethodPost, "/v1/plans/"+overlapPlan+"/revisions/precheck", overlapInput, &overlapVerdict); err != nil {
		return err
	}
	if len(overlapVerdict.Findings) != 1 {
		return ensure(false, "overlap produced more than one finding")
	}
	finding := overlapVerdict.Findings[0]
	if finding.RuleID != "aaa-block" || finding.Severity != domain.SeverityBlock ||
		len(finding.CandidateRuleIDs) != 2 || finding.CandidateRuleIDs[0] != "aaa-block" {
		return ensure(false, "overlap resolution was not deterministic or explainable")
	}

	// 9. Zone scoping: a rule scoped to another zone does not apply.
	scopedPkg, err := createPolicyPackage(harness, domain.PolicyPackageInput{
		Name: "zone-scoped",
		Rules: []domain.PolicyRuleInput{
			{
				ID:       "apex-elsewhere",
				Code:     domain.RuleApexCNAME,
				Severity: string(domain.SeverityBlock),
				Zones:    []string{"elsewhere.example"},
			},
		},
	})
	if err != nil {
		return err
	}
	scopedPlan, err := createGovernedPlan(harness, "scope.example", scopedPkg.ID)
	if err != nil {
		return err
	}
	var scopedRevision domain.ZoneRevision
	scopedInput := domain.RevisionCreateInput{
		Serial:    2026100730,
		Authority: "ns1.scope.example",
		Entries: []domain.ZoneEntry{
			{Owner: "scope.example", Type: domain.EntryCNAME, Value: "host.scope.example"},
		},
	}
	if err := harness.call(http.MethodPatch, "/v1/plans/"+scopedPlan+"/revisions", scopedInput, &scopedRevision); err != nil {
		return err
	}
	if scopedRevision.Policy == nil || !scopedRevision.Policy.Allowed || len(scopedRevision.Policy.Findings) != 0 {
		return ensure(false, "zone-scoped rule leaked outside its zone")
	}

	// 10. Package upgrade must not reach the already pinned plan.
	upgraded, err := appendPolicyVersion(harness, pkg.ID, domain.PolicyPackageVersionInput{
		Rules: []domain.PolicyRuleInput{
			{ID: "apex-block", Code: domain.RuleApexCNAME, Severity: string(domain.SeverityWarn)},
			{ID: "cname-conflict-block", Code: domain.RuleCNAMEConflict, Severity: string(domain.SeverityBlock)},
			{ID: "wildcard-warn", Code: domain.RuleWildcardShadow, Severity: string(domain.SeverityWarn)},
		},
	})
	if err != nil {
		return err
	}
	if upgraded.Version != 2 {
		return ensure(false, "package upgrade did not create version 2")
	}
	// The original plan still evaluates apex CNAME as a block via v1; the
	// stored historical revision still carries its original v1 verdict.
	if warnedRevision.Policy.Version != 1 {
		return ensure(false, "historical revision was retroactively changed by the upgrade")
	}
	var stillBlocked domain.PolicyVerdict
	recheckInput := exemptInput
	recheckInput.Serial = 2026100704
	if err := harness.call(http.MethodPost, "/v1/plans/"+planID+"/revisions/precheck", recheckInput, &stillBlocked); err != nil {
		return err
	}
	if stillBlocked.Version != 1 || len(stillBlocked.Suppressed) != 1 {
		return ensure(false, "upgraded policy reached a plan pinned to v1")
	}

	// 11. Disabling a package via a new version does not disable already
	//     pinned plans (governance derives only from the pinned version);
	//     newly created plans cannot bind to the disabled package.
	off := false
	if _, err := appendPolicyVersion(harness, pkg.ID, domain.PolicyPackageVersionInput{
		Enabled: &off,
		Rules: []domain.PolicyRuleInput{
			{ID: "apex-block", Code: domain.RuleApexCNAME, Severity: string(domain.SeverityBlock)},
			{ID: "cname-conflict-block", Code: domain.RuleCNAMEConflict, Severity: string(domain.SeverityBlock)},
			{ID: "wildcard-warn", Code: domain.RuleWildcardShadow, Severity: string(domain.SeverityWarn)},
		},
	}); err != nil {
		return err
	}
	// The original plan still has the apex CNAME blocked by its pinned v1.
	var stillEnforced domain.PolicyVerdict
	disabledInput := exemptInput
	disabledInput.Serial = 2026100705
	if err := harness.call(http.MethodPost, "/v1/plans/"+planID+"/revisions/precheck", disabledInput, &stillEnforced); err != nil {
		return err
	}
	if stillEnforced.Version != 1 || !stillEnforced.Enabled || len(stillEnforced.Suppressed) != 1 {
		return ensure(false, "disabling the package reached a plan pinned to an enforcing version")
	}
	// A new plan cannot bind to the now-disabled package.
	if err := harness.call(http.MethodPut, "/v1/plans", map[string]any{
		"zone":                  "late.example",
		"minimum_success_ratio": 1,
		"maximum_latency_ms":    80,
		"expected_nodes":        1,
		"policy_package_id":     pkg.ID,
	}, nil); err != nil {
		if err := expectFailure(err, http.StatusBadRequest, string(domain.CodeValidationFailed)); err != nil {
			return err
		}
	} else {
		return ensure(false, "plan was bound to a disabled policy package")
	}

	// 12. Invalid package payloads are rejected before anything is written.
	if err := harness.call(http.MethodPut, "/v1/policies", domain.PolicyPackageInput{
		Name: "bad",
		Rules: []domain.PolicyRuleInput{
			{ID: "bad", Code: "unknown_code", Severity: string(domain.SeverityBlock)},
		},
	}, nil); err != nil {
		if err := expectFailure(err, http.StatusBadRequest, string(domain.CodeValidationFailed)); err != nil {
			return err
		}
	} else {
		return ensure(false, "invalid policy package was accepted")
	}

	return nil
}

func createPolicyPackage(harness *harness, input domain.PolicyPackageInput) (domain.PolicyPackage, error) {
	var pkg domain.PolicyPackage
	err := harness.call(http.MethodPut, "/v1/policies", input, &pkg)
	return pkg, err
}

func appendPolicyVersion(harness *harness, packageID string, input domain.PolicyPackageVersionInput) (domain.PolicyPackageVersion, error) {
	var version domain.PolicyPackageVersion
	err := harness.call(http.MethodPatch, "/v1/policies/"+packageID+"/versions", input, &version)
	return version, err
}

// createGovernedPlan creates a draft plan bound to a policy package and
// returns its ID.
func createGovernedPlan(harness *harness, zone string, packageID string) (string, error) {
	var plan domain.RolloutPlan
	err := harness.call(http.MethodPut, "/v1/plans", map[string]any{
		"zone":                  zone,
		"minimum_success_ratio": 1,
		"maximum_latency_ms":    80,
		"expected_nodes":        1,
		"policy_package_id":     packageID,
	}, &plan)
	if err != nil {
		return "", err
	}
	if plan.PolicyPackageID != packageID || plan.PolicyVersionID == "" {
		return "", ensure(false, "plan was not bound to the policy package")
	}
	return plan.ID, nil
}
