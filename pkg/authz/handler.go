package authz

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/romrossi/authz-rebac/pkg/router"
)

// Handler provides HTTP handlers for authz operations.
type AuthzHandler struct {
	authzService AuthzService
	meta         Metadata
}

func NewAuthzHandler(authzService AuthzService, meta Metadata) *AuthzHandler {
	return &AuthzHandler{authzService: authzService, meta: meta}
}

// CheckPermission handles GET /permissions/<permission>?resource=<type:id>&subject=<type:id>
func (h *AuthzHandler) CheckPermission() router.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		start := time.Now()

		// Get query parameter 'resource'
		resource, err := parseObjectParam(params, "resource")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.meta.IsValidObject(*resource); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		// Get query parameter 'subject'
		subject, err := parseObjectParam(params, "subject")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.meta.IsValidObject(*subject); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		// Get query parameter 'permission'
		permission, err := parseStringParam(params, "permission")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.meta.IsValidPermission(*resource, permission); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		// Get query parameter 'show_matching_paths'
		showMatchingPaths, err := parseBoolParam(params, "show_matching_paths")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		// Build traversal request from request parameters
		tRequest := TraversalRequest{
			StartOn: *resource,
			Forward: true,
			StopOn:  subject,
		}

		// Check single permission
		permissionCheck, err := h.authzService.CheckPermissions(r.Context(), tRequest, showMatchingPaths)
		if err != nil {
			log.Printf("[ERROR] AuthzHandler.CheckPermission: s.CheckPermissions failed: %v", err)
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// Get single evaluation
		permissionEval := permissionCheck[0].PermissionEvals[permission]

		// Build OK response
		log.Printf("[INFO] AuthzHandler.CheckPermission: executed in %v", time.Since(start))
		write(w, http.StatusOK, permissionEval)
	}
}

// CheckPermission handles GET /permissions?resource_filter=<type:id>&subject_filter=<type:id>
func (h *AuthzHandler) CheckPermissions() router.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		start := time.Now()

		// Get query parameter 'resource_filter'
		resourceFilter, err := parseObjectParam(params, "resource_filter")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.meta.IsValidObjectType(*resourceFilter); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		// Get query parameter 'subject_filter'
		subjectFilter, err := parseObjectParam(params, "subject_filter")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.meta.IsValidObjectType(*subjectFilter); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if resourceFilter.ID == "" && subjectFilter.ID == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("either a resource ID or a subject ID must be provided"))
			return
		}

		// Get query parameter 'show_matching_paths'
		showMatchingPaths, err := parseBoolParam(params, "show_matching_paths")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		var tRequest TraversalRequest
		if resourceFilter.ID != "" {
			tRequest.StartOn = *resourceFilter
			tRequest.Forward = true

			if subjectFilter.ID != "" {
				tRequest.StopOn = subjectFilter
			} else {
				tRequest.StopOnTypes = []string{subjectFilter.Type}
			}
		} else {
			tRequest.StartOn = *subjectFilter
			tRequest.Forward = false

			if resourceFilter.ID != "" {
				tRequest.StopOn = resourceFilter
			} else {
				tRequest.StopOnTypes = []string{resourceFilter.Type}
			}
		}

		// Check permissions
		permissionEvals, err := h.authzService.CheckPermissions(r.Context(), tRequest, showMatchingPaths)
		if err != nil {
			log.Printf("[ERROR] AuthzHandler.CheckPermissions: s.CheckPermissions failed: %v", err)
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// Build OK response
		log.Printf("[INFO] AuthzHandler.CheckPermissions: executed in %v", time.Since(start))
		write(w, http.StatusOK, permissionEvals)
	}
}

// GetRelations handles GET /resources/{resource}/relations
func (h *AuthzHandler) ListResourceRelations() router.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		start := time.Now()

		// Get query parameter 'resource'
		resource, err := parseObjectParam(params, "resource")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		// Build traversal request
		tRequest := TraversalRequest{
			StartOn:     *resource,
			Forward:     true,
			StopOnTypes: []string{"user", "group"},
		}

		// List paths between the resource and all users/groups
		tResponse, err := h.authzService.ListEffectivePaths(r.Context(), tRequest)
		if err != nil {
			log.Printf("[ERROR] AuthzHandler.ListResourceRelations: s.ListEffectivePaths failed: %v", err)
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// Build OK response
		log.Printf("[INFO] AuthzHandler.ListResourceRelations: executed in %v", time.Since(start))
		write(w, http.StatusOK, tResponse)
	}
}

// ManageRelationship handles POST /relations
func (h *AuthzHandler) ManageRelationships() router.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		// Decode JSON request body
		var req map[string][]Relationship
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %s", err))
			return
		}

		// Validate all creation/delete requests
		for _, rels := range req {
			for _, rel := range rels {
				if err := h.meta.IsValidRelation(rel); err != nil {
					writeError(w, http.StatusBadRequest, err)
					return
				}
			}
		}

		// Execute all deletions
		if relationshipsToDelete, ok := req["delete"]; ok {
			if err := h.authzService.DeleteRelationships(r.Context(), relationshipsToDelete); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		}

		// Execute all creations
		if relationshipsToCreate, ok := req["create"]; ok {
			if err := h.authzService.CreateRelationships(r.Context(), relationshipsToCreate); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		}

		// Build OK response
		write(w, http.StatusOK, nil)
	}
}

func parseStringParam(params map[string]string, paramName string) (string, error) {
	raw, ok := params[paramName]
	if !ok || raw == "" {
		return "", fmt.Errorf("missing parameter '%s'", paramName)
	}
	return raw, nil
}

func parseBoolParam(params map[string]string, paramName string) (bool, error) {
	raw, ok := params[paramName]
	if !ok || raw == "" {
		return false, nil
	}

	val, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid parameter '%s': must be a boolean ('true' or 'false')", paramName)
	}

	return val, nil
}

func parseObjectParam(params map[string]string, paramName string) (*Object, error) {
	raw, ok := params[paramName]
	if !ok || raw == "" {
		return nil, fmt.Errorf("required parameter '%s'", paramName)
	}

	object_parts := strings.SplitN(raw, ":", 2)
	object := &Object{Type: object_parts[0]}

	if len(object_parts) == 2 {
		object.ID = object_parts[1]
	}

	return object, nil
}

func write(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if payload != nil {
		json.NewEncoder(w).Encode(payload)
	}
}

func writeError(w http.ResponseWriter, statusCode int, err error) {
	w.WriteHeader(statusCode)
	w.Write([]byte(err.Error()))
}
