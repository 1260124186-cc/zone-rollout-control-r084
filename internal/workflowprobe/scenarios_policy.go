package workflowprobe

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"solo-0014-zone-rollout-control/internal/domain"
)

func createPolicyBundle(harness *harness, input domain.PolicyBundleInput) (domain.PolicyBundle, error) {
	var bundle domain.PolicyBundle
	err := harness.call(http.MethodPut, "/v1/policies", input, &bundle)
	return bundle, err
}

func createBoundPlan(harness *harness, zone string, bundleID string) (domain.RolloutPlan, error) {
	var plan domain.RolloutPlan
	err := harness.call(http.MethodPut, "/v1/plans", domain.PlanCreateInput{
		Zone:                zone,
		MinimumSuccessRatio: 1,
		MaximumLatencyMS:    80,
		ExpectedNodes:       1,
		PolicyBundleID:      bundleID,
	}, &plan)
	return plan, err
}

func precheckRevision(harness *harness, planID string, input domain.RevisionCreateInput) (domain.PolicyConclusion, error) {
	var conclusion domain.PolicyConclusion
	err := harness.call(http.MethodPost, "/v1/plans/"+planID+"/policy-check", input, &conclusion)
	return conclusion, err
}

func appendRevision(harness *harness, planID string, input domain.RevisionCreateInput) (domain.ZoneRevision, error) {
	var revision domain.ZoneRevision
	err := harness.call(http.MethodPatch, "/v1/plans/"+planID+"/revisions", input, &revision)
	return revision, err
}

func conclusionsEqual(left domain.PolicyConclusion, right domain.PolicyConclusion) (bool, error) {
	leftJSON, err := json.Marshal(left)
	if err != nil {
		return false, fmt.Errorf("encode left conclusion: %w", err)
	}
	rightJSON, err := json.Marshal(right)
	if err != nil {
		return false, fmt.Errorf("encode right conclusion: %w", err)
	}
	return string(leftJSON) == string(rightJSON), nil
}

func runZonePolicyEnforcement() error {
	harness, err := newHarness()
	if err != nil {
		return err
	}
	defer harness.close()
	now := harness.clock.Now()

	bundle, err := createPolicyBundle(harness, domain.PolicyBundleInput{
		Name: "edge-guard",
		Rules: []domain.PolicyRuleInput{
			{Code: "apex_cname", Severity: "warn"},
			{Code: "apex_cname", Severity: "block", Zones: []string{"edge.example"}},
			{Code: "cname_conflict", Severity: "block", Zones: []string{"edge.example"}},
			{Code: "wildcard_shadow", Severity: "warn"},
		},
		Exceptions: []domain.PolicyExceptionInput{
			{
				RuleCode:  "wildcard_shadow",
				Owner:     "api.edge.example",
				Reason:    "managed api alias",
				ExpiresAt: now.Add(time.Hour),
			},
			{
				RuleCode:  "cname_conflict",
				Owner:     "dup.edge.example",
				Reason:    "legacy pair",
				ExpiresAt: now.Add(-time.Hour),
			},
		},
	})
	if err != nil {
		return err
	}
	if bundle.Version != 1 || len(bundle.Exceptions) != 2 {
		return ensure(false, "policy bundle v1 was not created with two exceptions")
	}
	activeException := bundle.Exceptions[0]
	expiredException := bundle.Exceptions[1]
	if activeException.ID == "" || expiredException.ID == "" {
		return ensure(false, "policy exceptions did not receive identifiers")
	}

	_, err = createPolicyBundle(harness, domain.PolicyBundleInput{
		Name:  "unknown-rule",
		Rules: []domain.PolicyRuleInput{{Code: "nonsense", Severity: "block"}},
	})
	if err := expectFailure(err, http.StatusBadRequest, string(domain.CodeValidationFailed)); err != nil {
		return err
	}
	_, err = createPolicyBundle(harness, domain.PolicyBundleInput{
		Name: "duplicate-rule",
		Rules: []domain.PolicyRuleInput{
			{Code: "apex_cname", Severity: "block"},
			{Code: "apex_cname", Severity: "warn"},
		},
	})
	if err := expectFailure(err, http.StatusBadRequest, string(domain.CodeValidationFailed)); err != nil {
		return err
	}

	upgraded, err := createPolicyBundle(harness, domain.PolicyBundleInput{
		Name:  "edge-guard",
		Rules: []domain.PolicyRuleInput{{Code: "apex_cname", Severity: "warn"}},
	})
	if err != nil {
		return err
	}
	if upgraded.Version != 2 {
		return ensure(false, "policy upgrade did not receive the next version")
	}

	plan, err := createBoundPlan(harness, "edge.example", bundle.ID)
	if err != nil {
		return err
	}
	if plan.PolicyBundleID != bundle.ID || plan.PolicyBundleVersion != 1 {
		return ensure(false, "plan did not pin the policy bundle version")
	}

	apexInput := domain.RevisionCreateInput{
		Serial:    100,
		Authority: "ns1.edge.example",
		Entries: []domain.ZoneEntry{
			{Owner: "edge.example", Type: domain.EntryCNAME, Value: "target.edge.example"},
		},
	}
	prechecked, err := precheckRevision(harness, plan.ID, apexInput)
	if err != nil {
		return err
	}
	if prechecked.Outcome != domain.OutcomeBlock || len(prechecked.Findings) != 1 ||
		prechecked.Findings[0].RuleCode != domain.RuleApexCNAME ||
		prechecked.Findings[0].Severity != domain.SeverityBlock {
		return ensure(false, "precheck did not resolve overlapping apex rules to block")
	}
	_, err = appendRevision(harness, plan.ID, apexInput)
	if err := expectFailure(err, http.StatusUnprocessableEntity, string(domain.CodePolicyBlocked)); err != nil {
		return err
	}
	var current domain.RolloutPlan
	if err := harness.call(http.MethodGet, "/v1/plans/"+plan.ID, nil, &current); err != nil {
		return err
	}
	if current.Version != 1 || current.LatestRevisionID != "" {
		return ensure(false, "blocked revision changed the plan")
	}

	wildcardInput := domain.RevisionCreateInput{
		Serial:    100,
		Authority: "ns1.edge.example",
		Entries: []domain.ZoneEntry{
			{Owner: "*.edge.example", Type: domain.EntryA, Value: "192.0.2.10"},
			{Owner: "api.edge.example", Type: domain.EntryA, Value: "192.0.2.20"},
		},
	}
	prechecked, err = precheckRevision(harness, plan.ID, wildcardInput)
	if err != nil {
		return err
	}
	if prechecked.Outcome != domain.OutcomePass || prechecked.SuppressedCount != 1 ||
		len(prechecked.Findings) != 1 || !prechecked.Findings[0].Suppressed ||
		prechecked.Findings[0].ExceptionID != activeException.ID {
		return ensure(false, "active exception did not suppress the wildcard shadow finding")
	}
	wildcardRevision, err := appendRevision(harness, plan.ID, wildcardInput)
	if err != nil {
		return err
	}
	if wildcardRevision.Policy == nil {
		return ensure(false, "pass conclusion was not stored on the revision")
	}
	same, err := conclusionsEqual(prechecked, *wildcardRevision.Policy)
	if err != nil {
		return err
	}
	if !same {
		return ensure(false, "precheck and append produced different conclusions")
	}

	conflictInput := domain.RevisionCreateInput{
		Serial:    200,
		Authority: "ns1.edge.example",
		Entries: []domain.ZoneEntry{
			{Owner: "dup.edge.example", Type: domain.EntryA, Value: "192.0.2.30"},
			{Owner: "dup.edge.example", Type: domain.EntryCNAME, Value: "edge.example"},
		},
	}
	prechecked, err = precheckRevision(harness, plan.ID, conflictInput)
	if err != nil {
		return err
	}
	if prechecked.Outcome != domain.OutcomeBlock ||
		len(prechecked.ExpiredExceptionIDs) != 1 ||
		prechecked.ExpiredExceptionIDs[0] != expiredException.ID {
		return ensure(false, "expired exception suppressed or was not explained")
	}
	_, err = appendRevision(harness, plan.ID, conflictInput)
	var conflictFailure *apiFailure
	if !errors.As(err, &conflictFailure) {
		return ensure(false, "policy block did not return an api failure")
	}
	if conflictFailure.Status != http.StatusUnprocessableEntity ||
		conflictFailure.Code != string(domain.CodePolicyBlocked) {
		return ensure(false, "cname conflict with expired exception was not blocked")
	}
	expiredIDs, ok := conflictFailure.Details["expired_exception_ids"].([]any)
	if !ok || len(expiredIDs) != 1 || expiredIDs[0] != expiredException.ID {
		return ensure(false, "blocked response did not explain the expired exception")
	}

	harness.clock.Advance(2 * time.Hour)
	prechecked, err = precheckRevision(harness, plan.ID, domain.RevisionCreateInput{
		Serial:    300,
		Authority: "ns1.edge.example",
		Entries:   wildcardInput.Entries,
	})
	if err != nil {
		return err
	}
	if prechecked.Outcome != domain.OutcomeWarn || prechecked.SuppressedCount != 0 ||
		len(prechecked.ExpiredExceptionIDs) != 1 ||
		prechecked.ExpiredExceptionIDs[0] != activeException.ID {
		return ensure(false, "expiring the exception did not reactivate the warning")
	}
	warnedRevision, err := appendRevision(harness, plan.ID, domain.RevisionCreateInput{
		Serial:    300,
		Authority: "ns1.edge.example",
		Entries:   wildcardInput.Entries,
	})
	if err != nil {
		return err
	}
	if warnedRevision.Policy == nil || warnedRevision.Policy.Outcome != domain.OutcomeWarn {
		return ensure(false, "warning conclusion was not stored on the revision")
	}
	var latest domain.ZoneRevision
	if err := harness.call(http.MethodGet, "/v1/plans/"+plan.ID+"/revisions/latest", nil, &latest); err != nil {
		return err
	}
	if latest.ID != warnedRevision.ID || latest.Policy == nil ||
		latest.Policy.Outcome != domain.OutcomeWarn || latest.Policy.BundleVersion != 1 {
		return ensure(false, "latest revision did not preserve the stored conclusion")
	}

	_, err = appendRevision(harness, plan.ID, domain.RevisionCreateInput{
		Serial:    400,
		Authority: "ns1.edge.example",
		Entries: []domain.ZoneEntry{
			{Owner: "edge.example", Type: domain.EntryCNAME, Value: "target.edge.example"},
		},
	})
	if err := expectFailure(err, http.StatusUnprocessableEntity, string(domain.CodePolicyBlocked)); err != nil {
		return err
	}

	upgradedPlan, err := createBoundPlan(harness, "edge.example", upgraded.ID)
	if err != nil {
		return err
	}
	relaxed, err := appendRevision(harness, upgradedPlan.ID, domain.RevisionCreateInput{
		Serial:    100,
		Authority: "ns1.edge.example",
		Entries: []domain.ZoneEntry{
			{Owner: "edge.example", Type: domain.EntryCNAME, Value: "target.edge.example"},
		},
	})
	if err != nil {
		return err
	}
	if relaxed.Policy == nil || relaxed.Policy.Outcome != domain.OutcomeWarn ||
		relaxed.Policy.BundleVersion != 2 {
		return ensure(false, "upgraded bundle did not apply to new plans only")
	}

	otherPlan, err := createBoundPlan(harness, "other.example", bundle.ID)
	if err != nil {
		return err
	}
	otherApex, err := appendRevision(harness, otherPlan.ID, domain.RevisionCreateInput{
		Serial:    100,
		Authority: "ns1.other.example",
		Entries: []domain.ZoneEntry{
			{Owner: "other.example", Type: domain.EntryCNAME, Value: "target.other.example"},
		},
	})
	if err != nil {
		return err
	}
	if otherApex.Policy == nil || otherApex.Policy.Outcome != domain.OutcomeWarn {
		return ensure(false, "zone-scoped block rule leaked into another zone")
	}
	otherConflict, err := appendRevision(harness, otherPlan.ID, domain.RevisionCreateInput{
		Serial:    200,
		Authority: "ns1.other.example",
		Entries: []domain.ZoneEntry{
			{Owner: "x.other.example", Type: domain.EntryA, Value: "192.0.2.40"},
			{Owner: "x.other.example", Type: domain.EntryCNAME, Value: "other.example"},
		},
	})
	if err != nil {
		return err
	}
	if otherConflict.Policy == nil || otherConflict.Policy.Outcome != domain.OutcomePass {
		return ensure(false, "zone-scoped cname conflict rule leaked into another zone")
	}

	var plainPlan domain.RolloutPlan
	if err := harness.call(http.MethodPut, "/v1/plans", domain.PlanCreateInput{
		Zone:                "plain.example",
		MinimumSuccessRatio: 1,
		MaximumLatencyMS:    80,
		ExpectedNodes:       1,
	}, &plainPlan); err != nil {
		return err
	}
	plainRevision, err := appendRevision(harness, plainPlan.ID, domain.RevisionCreateInput{
		Serial:    100,
		Authority: "ns1.plain.example",
		Entries: []domain.ZoneEntry{
			{Owner: "plain.example", Type: domain.EntryCNAME, Value: "target.plain.example"},
			{Owner: "y.plain.example", Type: domain.EntryA, Value: "192.0.2.50"},
			{Owner: "y.plain.example", Type: domain.EntryCNAME, Value: "plain.example"},
		},
	})
	if err != nil {
		return err
	}
	if plainRevision.Policy != nil {
		return ensure(false, "unbound plan stored a policy conclusion")
	}
	unbound, err := precheckRevision(harness, plainPlan.ID, domain.RevisionCreateInput{
		Serial:    200,
		Authority: "ns1.plain.example",
		Entries: []domain.ZoneEntry{
			{Owner: "plain.example", Type: domain.EntryA, Value: "192.0.2.60"},
		},
	})
	if err != nil {
		return err
	}
	if unbound.Outcome != domain.OutcomePass || unbound.BundleID != "" || unbound.RulesEvaluated != 0 {
		return ensure(false, "unbound plan did not return the pass-through conclusion")
	}
	_, err = appendRevision(harness, plainPlan.ID, domain.RevisionCreateInput{
		Serial:    200,
		Authority: "ns1.plain.example",
		Entries: []domain.ZoneEntry{
			{Owner: "*.plain.example", Type: domain.EntryA, Value: "192.0.2.70"},
		},
	})
	if err := expectFailure(err, http.StatusBadRequest, string(domain.CodeValidationFailed)); err != nil {
		return err
	}

	bulk, err := createPolicyBundle(harness, domain.PolicyBundleInput{
		Name:  "bulk-guard",
		Rules: []domain.PolicyRuleInput{{Code: "cname_conflict", Severity: "warn"}},
	})
	if err != nil {
		return err
	}
	bulkPlan, err := createBoundPlan(harness, "bulk.example", bulk.ID)
	if err != nil {
		return err
	}
	bulkEntries := make([]domain.ZoneEntry, 0, 240)
	for index := 0; index < 120; index++ {
		owner := fmt.Sprintf("host-%03d.bulk.example", index)
		bulkEntries = append(bulkEntries,
			domain.ZoneEntry{Owner: owner, Type: domain.EntryA, Value: "192.0.2.99"},
			domain.ZoneEntry{Owner: owner, Type: domain.EntryCNAME, Value: "target.bulk.example"},
		)
	}
	bulkInput := domain.RevisionCreateInput{
		Serial:    100,
		Authority: "ns1.bulk.example",
		Entries:   bulkEntries,
	}
	prechecked, err = precheckRevision(harness, bulkPlan.ID, bulkInput)
	if err != nil {
		return err
	}
	if !prechecked.Truncated || prechecked.Outcome != domain.OutcomeWarn ||
		prechecked.FindingCounts[string(domain.RuleCNAMEConflict)] != 120 ||
		len(prechecked.Findings) != domain.MaxPolicyFindings ||
		prechecked.Findings[0].Owner != "host-000.bulk.example" {
		return ensure(false, "large entry set did not produce a deterministic truncated conclusion")
	}
	bulkRevision, err := appendRevision(harness, bulkPlan.ID, bulkInput)
	if err != nil {
		return err
	}
	if bulkRevision.Policy == nil {
		return ensure(false, "bulk revision did not store its conclusion")
	}
	same, err = conclusionsEqual(prechecked, *bulkRevision.Policy)
	if err != nil {
		return err
	}
	if !same {
		return ensure(false, "bulk precheck and append produced different conclusions")
	}

	_, err = createBoundPlan(harness, "ghost.example", "pol_missing")
	return expectFailure(err, http.StatusNotFound, string(domain.CodeNotFound))
}
