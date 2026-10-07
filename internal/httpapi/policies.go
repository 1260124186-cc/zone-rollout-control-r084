package httpapi

import (
	"net/http"

	"solo-0014-zone-rollout-control/internal/domain"
)

func (s *Server) createPolicyPackage(w http.ResponseWriter, r *http.Request) {
	var input domain.PolicyPackageInput
	if err := decode(w, r, &input); err != nil {
		sendError(w, r, err)
		return
	}
	pkg, err := s.policies.CreatePackage(r.Context(), input)
	if err != nil {
		sendError(w, r, err)
		return
	}
	sendData(w, r, http.StatusCreated, pkg)
}

func (s *Server) getPolicyPackage(w http.ResponseWriter, r *http.Request) {
	pkg, err := s.policies.GetPackage(r.Context(), r.PathValue("id"))
	if err != nil {
		sendError(w, r, err)
		return
	}
	sendData(w, r, http.StatusOK, pkg)
}

func (s *Server) appendPolicyVersion(w http.ResponseWriter, r *http.Request) {
	var input domain.PolicyPackageVersionInput
	if err := decode(w, r, &input); err != nil {
		sendError(w, r, err)
		return
	}
	version, err := s.policies.AppendVersion(r.Context(), r.PathValue("id"), input)
	if err != nil {
		sendError(w, r, err)
		return
	}
	sendData(w, r, http.StatusCreated, version)
}

func (s *Server) listPolicyVersions(w http.ResponseWriter, r *http.Request) {
	versions, err := s.policies.ListVersions(r.Context(), r.PathValue("id"))
	if err != nil {
		sendError(w, r, err)
		return
	}
	sendData(w, r, http.StatusOK, map[string]any{"items": versions})
}

func (s *Server) getPolicyVersion(w http.ResponseWriter, r *http.Request) {
	version, err := s.policies.GetVersion(r.Context(), r.PathValue("versionId"))
	if err != nil {
		sendError(w, r, err)
		return
	}
	sendData(w, r, http.StatusOK, version)
}
