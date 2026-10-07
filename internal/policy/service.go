package policy

import (
	"context"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"solo-0014-zone-rollout-control/internal/domain"
	"solo-0014-zone-rollout-control/internal/platform"
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

// CreatePackage writes the package and its immutable version 1 in one
// transaction.
func (s *Service) CreatePackage(ctx context.Context, input domain.PolicyPackageInput) (domain.PolicyPackage, error) {
	now := s.clock.Now().UTC()
	normalized := domain.NormalizePolicyPackageInput(input)
	if err := validatePackageName(normalized.Name); err != nil {
		return domain.PolicyPackage{}, err
	}
	if err := domain.ValidatePolicyRules(normalized.Rules, normalized.Exceptions, now); err != nil {
		return domain.PolicyPackage{}, err
	}
	enabled := true
	if normalized.Enabled != nil {
		enabled = *normalized.Enabled
	}

	var pkg domain.PolicyPackage
	err := s.store.Write(ctx, func(state *domain.State) error {
		for _, existing := range state.Policies {
			if existing.Name == normalized.Name {
				return domain.NewError(domain.CodeConflict, "policy package name is already in use", map[string]any{
					"name": normalized.Name,
				})
			}
		}
		pkg = domain.PolicyPackage{
			ID:          s.ids.New("pol"),
			Name:        normalized.Name,
			Description: normalized.Description,
			Version:     1,
			Enabled:     enabled,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		version := buildVersion(s.ids.New("pvr"), pkg, 1, enabled, normalized.Rules, normalized.Exceptions, now)
		pkg.LatestVersionID = version.ID
		state.Policies[pkg.ID] = pkg
		state.PolicyVersions[version.ID] = version
		store.AddAudit(state, s.ids, "policy", pkg.ID, "created", now, map[string]any{
			"name":    pkg.Name,
			"version": 1,
		})
		return nil
	})
	return pkg, err
}

// AppendVersion creates the next immutable version. Existing versions and any
// revisions already pinned to them are never rewritten.
func (s *Service) AppendVersion(
	ctx context.Context,
	packageID string,
	input domain.PolicyPackageVersionInput,
) (domain.PolicyPackageVersion, error) {
	now := s.clock.Now().UTC()
	normalized := domain.NormalizePolicyVersionInput(input)
	if err := domain.ValidatePolicyRules(normalized.Rules, normalized.Exceptions, now); err != nil {
		return domain.PolicyPackageVersion{}, err
	}
	var created domain.PolicyPackageVersion
	err := s.store.Write(ctx, func(state *domain.State) error {
		pkg, ok := state.Policies[packageID]
		if !ok {
			return domain.NotFound("policy package", packageID)
		}
		nextNumber := pkg.Version + 1
		enabled := pkg.Enabled
		if normalized.Enabled != nil {
			enabled = *normalized.Enabled
		}
		created = buildVersion(s.ids.New("pvr"), pkg, nextNumber, enabled, normalized.Rules, normalized.Exceptions, now)
		state.PolicyVersions[created.ID] = created
		pkg.Version = nextNumber
		pkg.Enabled = enabled
		pkg.LatestVersionID = created.ID
		pkg.UpdatedAt = now
		state.Policies[packageID] = pkg
		store.AddAudit(state, s.ids, "policy", pkg.ID, "version_appended", now, map[string]any{
			"version": nextNumber,
		})
		return nil
	})
	return created, err
}

func (s *Service) GetPackage(ctx context.Context, packageID string) (domain.PolicyPackage, error) {
	var pkg domain.PolicyPackage
	err := s.store.Read(ctx, func(state *domain.State) error {
		found, ok := state.Policies[packageID]
		if !ok {
			return domain.NotFound("policy package", packageID)
		}
		pkg = found
		return nil
	})
	return pkg, err
}

func (s *Service) GetVersion(ctx context.Context, versionID string) (domain.PolicyPackageVersion, error) {
	var version domain.PolicyPackageVersion
	err := s.store.Read(ctx, func(state *domain.State) error {
		found, ok := state.PolicyVersions[versionID]
		if !ok {
			return domain.NotFound("policy version", versionID)
		}
		version = found
		return nil
	})
	return version, err
}

func (s *Service) ListVersions(ctx context.Context, packageID string) ([]domain.PolicyPackageVersion, error) {
	versions := make([]domain.PolicyPackageVersion, 0)
	err := s.store.Read(ctx, func(state *domain.State) error {
		if _, ok := state.Policies[packageID]; !ok {
			return domain.NotFound("policy package", packageID)
		}
		for _, version := range state.PolicyVersions {
			if version.PackageID == packageID {
				versions = append(versions, version)
			}
		}
		sort.Slice(versions, func(i, j int) bool { return versions[i].Version < versions[j].Version })
		return nil
	})
	return versions, err
}

// ResolveForPlan returns the package and the exact version a plan pins. Plans
// pin a package version at creation time and never move forward implicitly, so
// policy upgrades cannot reach historical revisions or existing plans.
func ResolveForPlan(
	state *domain.State,
	packageID string,
	versionID string,
) (domain.PolicyPackage, domain.PolicyPackageVersion, bool) {
	pkg, ok := state.Policies[packageID]
	if !ok {
		return domain.PolicyPackage{}, domain.PolicyPackageVersion{}, false
	}
	version, ok := state.PolicyVersions[versionID]
	if !ok || version.PackageID != packageID {
		return domain.PolicyPackage{}, domain.PolicyPackageVersion{}, false
	}
	return pkg, version, true
}

// ResolveLatest returns a package and its current latest version. It is used
// when binding a newly created plan to a policy package.
func ResolveLatest(state *domain.State, packageID string) (domain.PolicyPackage, domain.PolicyPackageVersion, bool) {
	pkg, ok := state.Policies[packageID]
	if !ok {
		return domain.PolicyPackage{}, domain.PolicyPackageVersion{}, false
	}
	version, ok := state.PolicyVersions[pkg.LatestVersionID]
	if !ok || version.PackageID != packageID {
		return domain.PolicyPackage{}, domain.PolicyPackageVersion{}, false
	}
	return pkg, version, true
}

func buildVersion(
	id string,
	pkg domain.PolicyPackage,
	number int,
	enabled bool,
	ruleInputs []domain.PolicyRuleInput,
	exceptionInputs []domain.PolicyExceptionInput,
	now time.Time,
) domain.PolicyPackageVersion {
	rules := make([]domain.PolicyRule, 0, len(ruleInputs))
	for _, input := range ruleInputs {
		ruleEnabled := true
		if input.Enabled != nil {
			ruleEnabled = *input.Enabled
		}
		rules = append(rules, domain.PolicyRule{
			ID:       input.ID,
			Code:     input.Code,
			Severity: domain.PolicySeverity(input.Severity),
			Zones:    append([]string(nil), input.Zones...),
			Enabled:  ruleEnabled,
		})
	}
	exceptions := make([]domain.PolicyException, 0, len(exceptionInputs))
	for _, input := range exceptionInputs {
		exceptions = append(exceptions, domain.PolicyException{
			ID:        input.ID,
			RuleCode:  input.RuleCode,
			Owner:     input.Owner,
			ExpiresAt: input.ExpiresAt.UTC(),
			Reason:    input.Reason,
		})
	}
	return domain.PolicyPackageVersion{
		ID:         id,
		PackageID:  pkg.ID,
		Version:    number,
		Enabled:    enabled,
		Rules:      rules,
		Exceptions: exceptions,
		CreatedAt:  now,
	}
}

func validatePackageName(name string) error {
	name = strings.TrimSpace(name)
	count := utf8.RuneCountInString(name)
	if count < 3 || count > domain.MaxPolicyNameRunes {
		return domain.Validation("policy package is invalid", map[string]any{
			"name": "must contain between 3 and 120 characters",
		})
	}
	return nil
}
