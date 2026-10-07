package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"solo-0014-zone-rollout-control/internal/domain"
)

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) {
	var input domain.PolicyBundleInput
	if err := decode(w, r, &input); err != nil {
		sendError(w, r, err)
		return
	}
	bundle, err := s.policies.Create(r.Context(), input)
	if err != nil {
		sendError(w, r, err)
		return
	}
	sendData(w, r, http.StatusCreated, bundle)
}

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			sendError(w, r, domain.Validation("limit must be an integer", map[string]any{"limit": raw}))
			return
		}
		limit = parsed
	}
	page, err := s.policies.List(
		r.Context(),
		strings.TrimSpace(strings.ToLower(r.URL.Query().Get("name"))),
		limit,
		r.URL.Query().Get("cursor"),
	)
	if err != nil {
		sendError(w, r, err)
		return
	}
	sendData(w, r, http.StatusOK, page)
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	bundle, err := s.policies.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		sendError(w, r, err)
		return
	}
	sendData(w, r, http.StatusOK, bundle)
}
