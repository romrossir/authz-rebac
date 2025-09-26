package authz

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
}

func NewAuthzHandler(authzService AuthzService) *AuthzHandler {
	return &AuthzHandler{authzService: authzService}
}

// CheckPermission handles GET /permissions/<permission>?resource=<type:id>&subject=<type:id>
func (h *AuthzHandler) CheckPermission() router.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		start := time.Now()

		// Get query parameter 'resource'
		resource, err := parseObjectParam(params, "resource")
		if err != nil {
			write(w, http.StatusBadRequest, err.Error())
			return
		}

		// Get query parameter 'subject'
		subject, err := parseObjectParam(params, "subject")
		if err != nil {
			write(w, http.StatusBadRequest, err.Error())
			return
		}

		// Get query parameter 'permission'
		permission, err := parseStringParam(params, "permission")
		if err != nil {
			write(w, http.StatusBadRequest, err.Error())
			return
		}

		// Get query parameter 'show_matching_paths'
		showMatchingPaths, err := parseBoolParam(params, "show_matching_paths")
		if err != nil {
			write(w, http.StatusBadRequest, err.Error())
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
			write(w, http.StatusInternalServerError, err)
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
		resourceFilter, err := parseObjectFilterParam(params, "resource_filter")
		if err != nil {
			write(w, http.StatusBadRequest, err)
			return
		}

		// Get query parameter 'subject_filter'
		subjectFilter, err := parseObjectFilterParam(params, "subject_filter")
		if err != nil {
			write(w, http.StatusBadRequest, err)
			return
		}

		// Get query parameter 'show_matching_paths'
		showMatchingPaths, err := parseBoolParam(params, "show_matching_paths")
		if err != nil {
			write(w, http.StatusBadRequest, err)
			return
		}

		var tRequest TraversalRequest
		if resourceFilter.Type != "" && resourceFilter.ID != "" {
			tRequest.StartOn = *resourceFilter
			tRequest.Forward = true

			if subjectFilter.Type != "" && subjectFilter.ID != "" {
				tRequest.StopOn = subjectFilter
			} else if subjectFilter.Type != "" {
				tRequest.StopOnTypes = []string{subjectFilter.Type}
			}
		} else if subjectFilter.Type != "" && subjectFilter.ID != "" {
			tRequest.StartOn = *subjectFilter
			tRequest.Forward = false

			if subjectFilter.Type != "" {
				tRequest.StopOnTypes = []string{resourceFilter.Type}
			}
		}

		// Check permissions
		permissionEvals, err := h.authzService.CheckPermissions(r.Context(), tRequest, showMatchingPaths)
		if err != nil {
			log.Printf("[ERROR] AuthzHandler.CheckPermissions: s.CheckPermissions failed: %v", err)
			write(w, http.StatusInternalServerError, err)
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
			write(w, http.StatusBadRequest, err)
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
			write(w, http.StatusInternalServerError, err)
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
		req, err := parseRequestBody[map[string][]Relationship](r)
		if err != nil {
			write(w, http.StatusBadRequest, err)
			return
		}

		// Execute all deletions
		relationshipsToDelete, ok := (*req)["delete"]
		if ok {
			for _, rel := range relationshipsToDelete {
				// Delete relationship
				err = h.authzService.DeleteRelationship(r.Context(), rel.Resource, rel.Subject)
				if err != nil {
					write(w, http.StatusInternalServerError, err)
					return
				}
			}
		}

		// Execute all creations
		relationshipsToCreate, ok := (*req)["create"]
		if ok {
			for _, rel := range relationshipsToCreate {
				// Create relationship
				err = h.authzService.CreateRelationship(r.Context(), rel.Resource, rel.Subject, rel.Relation)
				if err != nil {
					write(w, http.StatusInternalServerError, err)
					return
				}
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
		return nil, fmt.Errorf("missing parameter '%s'", paramName)
	}

	// Parse <type>:<id>
	object_parts := strings.SplitN(raw, ":", 2)
	if len(object_parts) != 2 {
		return nil, fmt.Errorf("invalid parameter '%s': expected format <type>:<id>", paramName)
	}

	return &Object{Type: object_parts[0], ID: object_parts[1]}, nil
}

func parseObjectFilterParam(params map[string]string, paramName string) (*Object, error) {
	raw, ok := params[paramName]
	if !ok || raw == "" {
		return nil, fmt.Errorf("missing parameter '%s'", paramName)
	}

	// Parse <type>[:<id>]
	object_parts := strings.SplitN(raw, ":", 2)
	object := &Object{Type: object_parts[0]}

	if len(object_parts) == 2 {
		object.ID = object_parts[1]
	}

	return object, nil
}

func parseRequestBody[T any](r *http.Request) (*T, error) {
	// Read the body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body")
	}
	r.Body.Close()

	// Replace body so handler can read it again
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Unmarshal into map
	var payload T
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		return nil, fmt.Errorf("invalid request body")
	}

	return &payload, nil
}

func write(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if payload != nil {
		json.NewEncoder(w).Encode(payload)
	}
}
