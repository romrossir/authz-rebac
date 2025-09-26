package authz

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/romrossi/authz-rebac/pkg/db"
	"gopkg.in/yaml.v3"
)

// Service defines the interface for Authz business logic operations.
type AuthzService interface {
	CheckPermissions(ctx context.Context, request TraversalRequest, showMatchingPaths bool) ([]PermissionCheckItem, error)
	CreateRelationship(ctx context.Context, resource Object, subject Object, relationLabel string) error
	DeleteRelationship(ctx context.Context, resource Object, subject Object) error
	ListEffectivePaths(ctx context.Context, request TraversalRequest) ([]TraversalResponseItem, error)
}

// serviceImpl is an implementation of the Authz Service.
type serviceImpl struct {
	authzRepo     AuthzRepository
	authzMetadata Metadata
}

//go:embed schema.yaml
var Schema []byte

// NewService creates a new instance of serviceImpl.
func NewService(authzRepo AuthzRepository) AuthzService {
	authzMetadata, err := LoadMetadata(Schema)
	if err != nil {
		panic(fmt.Sprintf("failed to load authz metadata: %v", err))
	}

	return &serviceImpl{authzRepo: authzRepo, authzMetadata: *authzMetadata}
}

func LoadMetadata(data []byte) (*Metadata, error) {
	var meta Metadata
	if err := yaml.Unmarshal(data, &meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

func (s *serviceImpl) CreateRelationship(ctx context.Context, resource Object, subject Object, relation string) error {
	return db.WithTransaction(ctx, func(txCtx context.Context) error {

		// Insert or update Relationship in DB
		return s.authzRepo.Insert(ctx, Relationship{
			Resource: resource,
			Subject:  subject,
			Relation: relation,
		})
	})
}

func (s *serviceImpl) DeleteRelationship(ctx context.Context, resource Object, subject Object) error {
	return db.WithTransaction(ctx, func(ctx context.Context) error {

		// Delete Relationship
		return s.authzRepo.Delete(ctx, resource, subject)
	})
}

// CheckPermissions evaluates permissions for a given TraversalRequest.
func (s *serviceImpl) CheckPermissions(
	ctx context.Context,
	tRequest TraversalRequest,
	showMatchingPaths bool,
) ([]PermissionCheckItem, error) {

	// Step 1: Get effective paths according to precedence rules
	tResponse, err := s.ListEffectivePaths(ctx, tRequest)
	if err != nil {
		return nil, err
	}

	// Step 2: Evaluate all permissions for each resource-subject pair
	results := make([]PermissionCheckItem, 0, len(tResponse))
	for _, item := range tResponse {
		results = append(results, PermissionCheckItem{
			Resource:        item.Resource,
			Subject:         item.Subject,
			PermissionEvals: s.evaluateAllPermissions(item.Resource, item.Paths, showMatchingPaths),
		})
	}

	return results, nil
}

// evaluateAllPermissions evaluates all defined permissions for a given resource and set of paths.
func (s *serviceImpl) evaluateAllPermissions(
	resource Object,
	paths [][]Relationship,
	showMatchingPaths bool,
) map[string]PermissionEval {

	perms := s.authzMetadata.Objects[resource.Type].Permissions
	evals := make(map[string]PermissionEval, len(perms))

	for permName, permDef := range perms {
		evals[permName] = s.evaluatePermission(permDef, paths, showMatchingPaths)
	}

	return evals
}

// evaluatePermission determines if a single permission is allowed based on the paths and definition.
// If showMatchingPaths is true, all matching paths are included; otherwise, the first match returns immediately.
func (s *serviceImpl) evaluatePermission(
	permission PermissionDefinition,
	paths [][]Relationship,
	showMatchingPaths bool,
) PermissionEval {

	eval := PermissionEval{
		Allowed: false,
	}

	// Step 1: Deny if any path contains an excluded relation
	for _, except := range permission.Except {
		for _, path := range paths {
			if pathContains(path, except) {
				// Forbidden → immediately return
				return eval
			}
		}
	}

	// Step 2: Allow if any path contains an allowed relation
	for _, anyOf := range permission.AnyOf {
		for _, path := range paths {
			if pathContains(path, anyOf) {
				eval.Allowed = true

				if showMatchingPaths {
					eval.MatchingPaths = append(eval.MatchingPaths, path)
				} else {
					// No need to keep paths → return immediately
					return eval
				}
			}
		}
	}

	// If showMatchingPaths is true, MatchingPaths may be empty (JSON omits it via `omitempty`)
	return eval
}

// ListEffectivePaths returns the traversal response items with only the effective paths
// after applying precedence rules. Precedence rules (in order) are:
//  1. Paths containing "administrator" take precedence over those without.
//  2. Paths without "member" take precedence over those with "member".
//  3. Paths with fewer "parent" relationships (closer in hierarchy) take precedence.
//
// If multiple paths are equally effective according to these rules, all are kept.
func (s *serviceImpl) ListEffectivePaths(ctx context.Context, tRequest TraversalRequest) ([]TraversalResponseItem, error) {
	tResponse, err := s.authzRepo.ListPaths(ctx, tRequest)
	if err != nil {
		return nil, err
	}

	// Apply precedence rules to each response item
	for i := range tResponse {
		tResponse[i].Paths = effectivePaths(tResponse[i].Paths)
	}

	return tResponse, nil
}

// effectivePaths filters a list of paths and returns only the effective ones
// based on the precedence rules described above.
func effectivePaths(paths [][]Relationship) [][]Relationship {
	if len(paths) == 0 {
		return nil
	}

	effective := [][]Relationship{paths[0]}
	for _, p := range paths[1:] {
		cmp := compare(p, effective[0])
		if cmp < 0 {
			effective = [][]Relationship{p} // found a more effective path → reset
		} else if cmp == 0 {
			effective = append(effective, p) // equally effective → keep
		}
	}
	return effective
}

// compare returns negative if a < b (a is more effective), 0 if equal, positive if a > b
func compare(a, b []Relationship) int {
	// Rule 1: administrator takes precedence
	aHasAdmin, bHasAdmin := pathContains(a, "administrator"), pathContains(b, "administrator")
	if aHasAdmin != bHasAdmin {
		if aHasAdmin {
			return -1 // a has administrator → better
		}
		return 1 // b has administrator → better
	}

	// Rule 2: prefer paths without member
	aHasMember, bHasMember := pathContains(a, "member"), pathContains(b, "member")
	if aHasMember != bHasMember {
		if !aHasMember {
			return -1 // a has no member → better
		}
		return 1 // b has no member → better
	}

	// Rule 3: fewer parent relationships → closer in hierarchy
	aParents, bParents := pathCount(a, "parent"), pathCount(b, "parent")
	if aParents != bParents {
		return aParents - bParents // fewer parents is better
	}

	// equally effective
	return 0
}

func pathContains(path []Relationship, relation string) bool {
	for _, r := range path {
		if r.Relation == relation {
			return true
		}
	}
	return false
}

func pathCount(path []Relationship, relation string) int {
	count := 0
	for _, r := range path {
		if r.Relation == relation {
			count++
		}
	}
	return count
}
