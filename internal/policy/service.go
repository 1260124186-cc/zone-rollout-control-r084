package policy

import (
	"context"
	"sort"

	"solo-0014-zone-rollout-control/internal/domain"
	"solo-0014-zone-rollout-control/internal/platform"
	"solo-0014-zone-rollout-control/internal/store"
)

// Service manages immutable, versioned policy bundles. A bundle is frozen
// the moment it is created; publishing an upgrade means creating the next
// version under the same name, which never rewrites earlier versions.
type Service struct {
	store *store.Store
	clock platform.Clock
	ids   platform.IDGenerator
}

func New(stateStore *store.Store, clock platform.Clock, ids platform.IDGenerator) *Service {
	return &Service{store: stateStore, clock: clock, ids: ids}
}

func (s *Service) Create(ctx context.Context, input domain.PolicyBundleInput) (domain.PolicyBundle, error) {
	if err := domain.ValidatePolicyBundleInput(input); err != nil {
		return domain.PolicyBundle{}, err
	}
	input = domain.NormalizePolicyBundleInput(input)
	now := s.clock.Now().UTC()
	bundle := domain.PolicyBundle{
		ID:         s.ids.New("pol"),
		Name:       input.Name,
		Rules:      make([]domain.PolicyRule, 0, len(input.Rules)),
		Exceptions: make([]domain.PolicyException, 0, len(input.Exceptions)),
		CreatedAt:  now,
	}
	for _, rule := range input.Rules {
		bundle.Rules = append(bundle.Rules, domain.PolicyRule{
			Code:     domain.PolicyRuleCode(rule.Code),
			Severity: domain.PolicySeverity(rule.Severity),
			Zones:    append([]string{}, rule.Zones...),
		})
	}
	for _, exception := range input.Exceptions {
		bundle.Exceptions = append(bundle.Exceptions, domain.PolicyException{
			ID:        s.ids.New("pex"),
			RuleCode:  domain.PolicyRuleCode(exception.RuleCode),
			Zone:      exception.Zone,
			Owner:     exception.Owner,
			Reason:    exception.Reason,
			ExpiresAt: exception.ExpiresAt.UTC(),
		})
	}
	err := s.store.Write(ctx, func(state *domain.State) error {
		version := 0
		for _, existing := range state.PolicyBundles {
			if existing.Name == bundle.Name && existing.Version > version {
				version = existing.Version
			}
		}
		bundle.Version = version + 1
		state.PolicyBundles[bundle.ID] = bundle
		store.AddAudit(state, s.ids, "policy_bundle", bundle.ID, "created", now, map[string]any{
			"name":    bundle.Name,
			"version": bundle.Version,
		})
		return nil
	})
	return bundle, err
}

func (s *Service) Get(ctx context.Context, bundleID string) (domain.PolicyBundle, error) {
	var bundle domain.PolicyBundle
	err := s.store.Read(ctx, func(state *domain.State) error {
		found, ok := state.PolicyBundles[bundleID]
		if !ok {
			return domain.NotFound("policy_bundle", bundleID)
		}
		bundle = found
		return nil
	})
	return bundle, err
}

func (s *Service) List(
	ctx context.Context,
	nameFilter string,
	limit int,
	cursor string,
) (domain.PolicyBundlePage, error) {
	if limit < 1 || limit > 100 {
		return domain.PolicyBundlePage{}, domain.Validation("limit must be between 1 and 100", map[string]any{
			"limit": limit,
		})
	}
	after, err := platform.DecodeCursor(cursor)
	if err != nil {
		return domain.PolicyBundlePage{}, domain.Validation("cursor is invalid", nil)
	}
	var page domain.PolicyBundlePage
	err = s.store.Read(ctx, func(state *domain.State) error {
		items := make([]domain.PolicyBundle, 0, len(state.PolicyBundles))
		for _, bundle := range state.PolicyBundles {
			if nameFilter != "" && bundle.Name != nameFilter {
				continue
			}
			if after != "" && bundle.ID <= after {
				continue
			}
			items = append(items, bundle)
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
