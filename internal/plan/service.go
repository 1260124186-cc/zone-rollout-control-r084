package plan

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"time"

	"solo-0014-zone-rollout-control/internal/domain"
	"solo-0014-zone-rollout-control/internal/platform"
	policysvc "solo-0014-zone-rollout-control/internal/policy"
	"solo-0014-zone-rollout-control/internal/store"
)

type Service struct {
	store *store.Store
	clock platform.Clock
	ids   platform.IDGenerator
}

func New(stateStore *store.Store, clock platform.Clock, ids platform.IDGenerator) *Service {
	return &Service{store: stateStore, clock: clock, ids: ids}
}

func (s *Service) Create(ctx context.Context, input domain.PlanCreateInput) (domain.RolloutPlan, error) {
	if err := domain.ValidatePlanInput(input); err != nil {
		return domain.RolloutPlan{}, err
	}
	input = domain.NormalizePlanInput(input)
	now := s.clock.Now().UTC()
	plan := domain.RolloutPlan{
		ID:                  s.ids.New("pln"),
		Zone:                input.Zone,
		State:               domain.PlanDraft,
		MinimumSuccessRatio: input.MinimumSuccessRatio,
		MaximumLatencyMS:    input.MaximumLatencyMS,
		ExpectedNodes:       input.ExpectedNodes,
		Version:             1,
		CreatedAt:           now,
	}
	err := s.store.Write(ctx, func(state *domain.State) error {
		if input.PolicyPackageID != "" {
			pkg, version, ok := policysvc.ResolveLatest(state, input.PolicyPackageID)
			if !ok {
				return domain.Validation("plan input is invalid", map[string]any{
					"policy_package_id": "does not reference an existing policy package",
				})
			}
			if !pkg.Enabled || !version.Enabled {
				return domain.Validation("plan input is invalid", map[string]any{
					"policy_package_id": "policy package is not enabled",
				})
			}
			plan.PolicyPackageID = pkg.ID
			plan.PolicyVersionID = version.ID
		}
		state.Plans[plan.ID] = plan
		store.AddAudit(state, s.ids, "plan", plan.ID, "created", now, map[string]any{
			"zone":           plan.Zone,
			"policy_package": plan.PolicyPackageID,
			"policy_version": plan.PolicyVersionID,
		})
		return nil
	})
	return plan, err
}

func (s *Service) AddRevision(
	ctx context.Context,
	planID string,
	input domain.RevisionCreateInput,
) (domain.ZoneRevision, error) {
	now := s.clock.Now().UTC()
	var created domain.ZoneRevision
	err := s.store.Write(ctx, func(state *domain.State) error {
		plan, ok := state.Plans[planID]
		if !ok {
			return domain.NotFound("plan", planID)
		}
		if plan.State != domain.PlanDraft {
			return domain.InvalidState("revisions can be added only while plan is draft", map[string]any{
				"plan_id": planID,
				"state":   plan.State,
			})
		}

		normalized, verdict, err := s.evaluateInput(state, plan, input, now)
		if err != nil {
			return err
		}
		if err := validateRevisionSequence(state, planID, normalized.Serial); err != nil {
			return err
		}

		var policySnapshot *domain.PolicyVerdict
		if verdict.Enabled {
			if !verdict.Allowed {
				return policyViolation(verdict)
			}
			policySnapshot = &verdict
		}

		created = domain.ZoneRevision{
			ID:         s.ids.New("rev"),
			PlanID:     planID,
			Serial:     normalized.Serial,
			Authority:  normalized.Authority,
			Entries:    append([]domain.ZoneEntry(nil), normalized.Entries...),
			EntryCount: len(normalized.Entries),
			Policy:     policySnapshot,
			CreatedAt:  now,
		}
		state.Revisions[created.ID] = created
		plan.LatestRevisionID = created.ID
		plan.Version++
		state.Plans[planID] = plan
		auditAttributes := map[string]any{
			"plan_id": planID,
			"serial":  created.Serial,
		}
		if policySnapshot != nil {
			auditAttributes["policy_warnings"] = countWarnings(*policySnapshot)
		}
		store.AddAudit(state, s.ids, "revision", created.ID, "added", now, auditAttributes)
		return nil
	})
	return created, err
}

// PrecheckRevision runs exactly the same normalization, sequence and policy
// evaluation as AddRevision but persists nothing. Plans with no binding, and
// plans whose pinned version is not enforcing, keep the original behavior and
// receive an enabled=false conclusion.
func (s *Service) PrecheckRevision(
	ctx context.Context,
	planID string,
	input domain.RevisionCreateInput,
) (domain.PolicyVerdict, error) {
	now := s.clock.Now().UTC()
	var verdict domain.PolicyVerdict
	err := s.store.Read(ctx, func(state *domain.State) error {
		plan, ok := state.Plans[planID]
		if !ok {
			return domain.NotFound("plan", planID)
		}
		if plan.State != domain.PlanDraft {
			return domain.InvalidState("revisions can be checked only while plan is draft", map[string]any{
				"plan_id": planID,
				"state":   plan.State,
			})
		}
		normalized, evaluated, err := s.evaluateInput(state, plan, input, now)
		if err != nil {
			return err
		}
		if err := validateRevisionSequence(state, planID, normalized.Serial); err != nil {
			return err
		}
		verdict = evaluated
		return nil
	})
	return verdict, err
}

// evaluateInput normalizes and validates candidate revision content and
// produces the deterministic policy conclusion. It is the single code path
// shared by PrecheckRevision and AddRevision, guaranteeing both surfaces
// return the same verdict for the same content at the same clock instant.
//
// Whether a plan is governed is derived only from the immutable version it
// pinned at creation, never from the package's current toggle. Plans with no
// binding keep their original (wildcard-rejecting, no-snapshot) behavior.
func (s *Service) evaluateInput(
	state *domain.State,
	plan domain.RolloutPlan,
	input domain.RevisionCreateInput,
	now time.Time,
) (domain.RevisionCreateInput, domain.PolicyVerdict, error) {
	// Resolve the pinned version first so normalization picks the correct
	// owner grammar (wildcards only when governed).
	var pkg domain.PolicyPackage
	var version domain.PolicyPackageVersion
	governed := false
	if plan.PolicyPackageID != "" {
		resolvedPackage, resolvedVersion, ok := policysvc.ResolveForPlan(state, plan.PolicyPackageID, plan.PolicyVersionID)
		if !ok {
			return domain.RevisionCreateInput{}, domain.PolicyVerdict{}, domain.NewError(
				domain.CodeStorageFailure, "plan references a missing policy version", map[string]any{
					"policy_package_id": plan.PolicyPackageID,
					"policy_version_id": plan.PolicyVersionID,
				})
		}
		pkg, version = resolvedPackage, resolvedVersion
		governed = version.Enabled
	}

	var (
		normalized domain.RevisionCreateInput
		err        error
	)
	if governed {
		normalized, err = domain.NormalizeRevisionInputForPolicy(input)
	} else {
		normalized, err = domain.NormalizeRevisionInputDefault(input)
	}
	if err != nil {
		return domain.RevisionCreateInput{}, domain.PolicyVerdict{}, err
	}
	if err := domain.ValidateRevisionInput(normalized); err != nil {
		return domain.RevisionCreateInput{}, domain.PolicyVerdict{}, err
	}

	if !governed {
		// Either no binding, or a pinned version that is not enforcing. In
		// both cases the original behavior applies and no policy snapshot is
		// stored; the verdict is informational only (enabled=false).
		return normalized, domain.PolicyVerdict{
			Enabled:     false,
			Allowed:     true,
			EvaluatedAt: now,
			Findings:    []domain.PolicyFinding{},
			Suppressed:  []domain.SuppressedFinding{},
		}, nil
	}

	verdict := domain.EvaluatePolicy(plan.Zone, normalized.Entries, pkg, version, now)
	return normalized, verdict, nil
}

// validateRevisionSequence enforces strictly increasing serials within a plan.
func validateRevisionSequence(state *domain.State, planID string, serial uint32) error {
	for _, revision := range state.Revisions {
		if revision.PlanID != planID {
			continue
		}
		if revision.Serial == serial {
			return domain.NewError(domain.CodeDuplicateRevision, "plan already contains this serial", map[string]any{
				"plan_id": planID,
				"serial":  serial,
			})
		}
		if revision.Serial > serial {
			return domain.Validation("revision serial must increase", map[string]any{
				"serial": serial,
				"latest": revision.Serial,
			})
		}
	}
	return nil
}

func policyViolation(verdict domain.PolicyVerdict) *domain.DomainError {
	blocks := make([]domain.PolicyFinding, 0)
	for _, finding := range verdict.Findings {
		if finding.Severity == domain.SeverityBlock {
			blocks = append(blocks, finding)
		}
	}
	return domain.NewError(domain.CodePolicyViolation, "revision violates blocking zone policy", map[string]any{
		"package_id": verdict.PackageID,
		"version":    verdict.Version,
		"blocking":   blocks,
	})
}

func countWarnings(verdict domain.PolicyVerdict) int {
	count := 0
	for _, finding := range verdict.Findings {
		if finding.Severity == domain.SeverityWarn {
			count++
		}
	}
	return count
}

func (s *Service) Activate(
	ctx context.Context,
	planID string,
	expectedVersion uint64,
) (domain.RolloutPlan, error) {
	var plan domain.RolloutPlan
	err := s.store.Write(ctx, func(state *domain.State) error {
		current, ok := state.Plans[planID]
		if !ok {
			return domain.NotFound("plan", planID)
		}
		if current.Version != expectedVersion {
			return versionConflict(planID, expectedVersion, current.Version)
		}
		now := s.clock.Now().UTC()
		if err := domain.ActivatePlan(&current, now); err != nil {
			return err
		}
		state.Plans[planID] = current
		store.AddAudit(state, s.ids, "plan", planID, "activated", now, map[string]any{
			"version": current.Version,
		})
		plan = current
		return nil
	})
	return plan, err
}

func (s *Service) Complete(
	ctx context.Context,
	planID string,
	expectedVersion uint64,
) (domain.RolloutPlan, error) {
	var plan domain.RolloutPlan
	err := s.store.Write(ctx, func(state *domain.State) error {
		current, ok := state.Plans[planID]
		if !ok {
			return domain.NotFound("plan", planID)
		}
		if current.Version != expectedVersion {
			return versionConflict(planID, expectedVersion, current.Version)
		}
		now := s.clock.Now().UTC()
		if err := domain.CompletePlan(&current, now); err != nil {
			return err
		}
		state.Plans[planID] = current
		store.AddAudit(state, s.ids, "plan", planID, "completed", now, map[string]any{
			"version": current.Version,
		})
		plan = current
		return nil
	})
	return plan, err
}

func (s *Service) Get(ctx context.Context, planID string) (domain.RolloutPlan, error) {
	var plan domain.RolloutPlan
	err := s.store.Read(ctx, func(state *domain.State) error {
		found, ok := state.Plans[planID]
		if !ok {
			return domain.NotFound("plan", planID)
		}
		plan = found
		return nil
	})
	return plan, err
}

func (s *Service) LatestRevision(
	ctx context.Context,
	planID string,
) (domain.ZoneRevision, error) {
	var revision domain.ZoneRevision
	err := s.store.Read(ctx, func(state *domain.State) error {
		plan, ok := state.Plans[planID]
		if !ok {
			return domain.NotFound("plan", planID)
		}
		if plan.LatestRevisionID == "" {
			return domain.NotFound("revision", planID)
		}
		found, ok := state.Revisions[plan.LatestRevisionID]
		if !ok {
			return domain.NewError(domain.CodeStorageFailure, "plan references a missing revision", map[string]any{
				"revision_id": plan.LatestRevisionID,
			})
		}
		revision = found
		return nil
	})
	return revision, err
}

func (s *Service) List(
	ctx context.Context,
	stateFilter domain.PlanState,
	limit int,
	cursor string,
) (domain.PlanPage, error) {
	if limit < 1 || limit > 100 {
		return domain.PlanPage{}, domain.Validation("limit must be between 1 and 100", map[string]any{
			"limit": limit,
		})
	}
	after, err := platform.DecodeCursor(cursor)
	if err != nil {
		return domain.PlanPage{}, domain.Validation("cursor is invalid", nil)
	}
	var page domain.PlanPage
	err = s.store.Read(ctx, func(state *domain.State) error {
		items := make([]domain.RolloutPlan, 0, len(state.Plans))
		for _, plan := range state.Plans {
			if stateFilter != "" && plan.State != stateFilter {
				continue
			}
			if after != "" && plan.ID <= after {
				continue
			}
			items = append(items, plan)
		}
		sort.Slice(items, func(i, j int) bool {
			return items[i].ID < items[j].ID
		})
		page.Meta.Limit = limit
		if len(items) > limit {
			page.Items = append(page.Items, items[:limit]...)
			page.Meta.NextCursor = platform.EncodeCursor(items[limit-1].ID)
			return nil
		}
		page.Items = append(page.Items, items...)
		return nil
	})
	return page, err
}

func (s *Service) RevisionExists(
	ctx context.Context,
	planID string,
	serial uint32,
	authority string,
	entries []domain.ZoneEntry,
) (bool, error) {
	exists := false
	err := s.store.Read(ctx, func(state *domain.State) error {
		for _, revision := range state.Revisions {
			if revision.PlanID != planID || revision.Serial != serial || revision.Authority != authority {
				continue
			}
			if reflect.DeepEqual(revision.Entries, entries) {
				exists = true
				return nil
			}
		}
		return nil
	})
	return exists, err
}

func RevisionDigest(revision domain.ZoneRevision) string {
	payload, _ := json.Marshal(struct {
		Serial    uint32
		Authority string
		Entries   []domain.ZoneEntry
	}{
		Serial:    revision.Serial,
		Authority: revision.Authority,
		Entries:   revision.Entries,
	})
	return string(payload)
}

func versionConflict(id string, expected uint64, actual uint64) *domain.DomainError {
	return domain.NewError(domain.CodeVersionConflict, "plan version does not match", map[string]any{
		"plan_id":  id,
		"expected": expected,
		"actual":   actual,
	})
}
