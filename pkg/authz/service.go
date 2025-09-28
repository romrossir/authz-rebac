package authz

import (
	"context"
	_ "embed"

	"github.com/romrossi/authz-rebac/pkg/db"
)

// AuthzService defines the business logic for authorization operations.
type AuthzService interface {
	// CheckPermissions evaluates permissions for a given traversal request.
	CheckPermissions(ctx context.Context, request TraversalRequest, showMatchingPaths bool) ([]PermissionCheckItem, error)

	// CreateRelationship inserts multiple relationships.
	CreateRelationships(ctx context.Context, relationships []Relationship) error

	// DeleteRelationship removes multiple relationships.
	DeleteRelationships(ctx context.Context, relationships []Relationship) error

	// ListEffectivePaths returns all effective paths discovered during traversal,
	// reduced according to precedence rules.
	ListEffectivePaths(ctx context.Context, request TraversalRequest) ([]TraversalResponseItem, error)
}

// serviceImpl implements AuthzService.
type serviceImpl struct {
	authzRepo AuthzRepository
	meta      Metadata
}

// NewService constructs a new AuthzService backed by the given repository.
func NewService(authzRepo AuthzRepository, meta Metadata) AuthzService {
	return &serviceImpl{authzRepo: authzRepo, meta: meta}
}

// CreateRelationship inserts relationships into the repository within a transaction.
func (s *serviceImpl) CreateRelationships(ctx context.Context, relationships []Relationship) error {
	return db.WithTransaction(ctx, func(txCtx context.Context) error {
		return s.authzRepo.InsertBulk(txCtx, relationships)
	})
}

// DeleteRelationship removes a relationships from the repository within a transaction.
func (s *serviceImpl) DeleteRelationships(ctx context.Context, relationships []Relationship) error {
	return db.WithTransaction(ctx, func(txCtx context.Context) error {
		return s.authzRepo.DeleteBulk(txCtx, relationships)
	})
}

// CheckPermissions evaluates permissions for each resource-subject pair
// discovered by traversing relationships from the given request.
func (s *serviceImpl) CheckPermissions(
	ctx context.Context,
	request TraversalRequest,
	showMatchingPaths bool,
) ([]PermissionCheckItem, error) {

	// Step 1: Resolve effective paths according to precedence rules
	tResponse, err := s.ListEffectivePaths(ctx, request)
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

// evaluateAllPermissions evaluates all permissions defined for a resource type.
func (s *serviceImpl) evaluateAllPermissions(
	resource Object,
	paths [][]Relationship,
	showMatchingPaths bool,
) map[string]PermissionEval {

	perms := s.meta.Objects[resource.Type].Permissions
	evals := make(map[string]PermissionEval, len(perms))

	for name, def := range perms {
		evals[name] = s.evaluatePermission(def, paths, showMatchingPaths)
	}
	return evals
}

// evaluatePermission checks whether a single permission is allowed,
// based on the given traversal paths and permission definition.
//
// Rules:
//  1. If any path contains an excluded relation (Except), deny immediately.
//  2. If any path contains an allowed relation (AnyOf), grant permission.
//     - If showMatchingPaths is true, collect all matching paths.
//     - Otherwise, return after the first match.
func (s *serviceImpl) evaluatePermission(
	permission PermissionDefinition,
	paths [][]Relationship,
	showMatchingPaths bool,
) PermissionEval {

	eval := PermissionEval{Allowed: false}

	// Rule 1: deny if any excluded relation is found
	for _, except := range permission.Except {
		for _, path := range paths {
			if pathContains(path, except) {
				return eval
			}
		}
	}

	// Rule 2: allow if any required relation is found
	for _, anyOf := range permission.AnyOf {
		for _, path := range paths {
			if pathContains(path, anyOf) {
				eval.Allowed = true
				if showMatchingPaths {
					eval.MatchingPaths = append(eval.MatchingPaths, path)
				} else {
					return eval // return early if paths are not needed
				}
			}
		}
	}

	return eval
}

// ListEffectivePaths reduces all traversal paths by applying precedence rules:
//  1. Paths containing "administrator" take precedence over those without.
//  2. Paths without "member" take precedence over those with "member".
//  3. Paths with fewer "parent" relations take precedence (closer in hierarchy).
//
// If multiple paths are equally effective, all are kept.
func (s *serviceImpl) ListEffectivePaths(ctx context.Context, request TraversalRequest) ([]TraversalResponseItem, error) {
	tResponse, err := s.authzRepo.ListPaths(ctx, request)
	if err != nil {
		return nil, err
	}

	for i := range tResponse {
		tResponse[i].Paths = effectivePaths(tResponse[i].Paths)
	}
	return tResponse, nil
}

// effectivePaths filters paths down to only the most effective ones
// according to the precedence rules defined in compare.
func effectivePaths(paths [][]Relationship) [][]Relationship {
	if len(paths) == 0 {
		return nil
	}

	effective := [][]Relationship{paths[0]}
	for _, p := range paths[1:] {
		switch cmp := compare(p, effective[0]); {
		case cmp < 0:
			effective = [][]Relationship{p} // found a better path -> reset
		case cmp == 0:
			effective = append(effective, p) // equally effective -> keep
		}
	}
	return effective
}

// compare returns:
//   - negative if a is more effective than b
//   - zero if equally effective
//   - positive if a is less effective than b
func compare(a, b []Relationship) int {
	// Rule 1: administrator relation takes precedence
	aHasAdmin, bHasAdmin := pathContains(a, "administrator"), pathContains(b, "administrator")
	if aHasAdmin != bHasAdmin {
		if aHasAdmin {
			return -1 // a is better
		}
		return 1 // b is better
	}

	// Rule 2: prefer paths without "member"
	aHasMember, bHasMember := pathContains(a, "member"), pathContains(b, "member")
	if aHasMember != bHasMember {
		if !aHasMember {
			return -1 // a is better
		}
		return 1 // b is better
	}

	// Rule 3: fewer "parent" relations is better
	aParents, bParents := pathCount(a, "parent"), pathCount(b, "parent")
	if aParents != bParents {
		return aParents - bParents
	}

	return 0 // equally effective
}

// pathContains reports whether the path includes a relation with the given label.
func pathContains(path []Relationship, relation string) bool {
	for _, r := range path {
		if r.Relation == relation {
			return true
		}
	}
	return false
}

// pathCount returns the number of times a relation appears in the path.
func pathCount(path []Relationship, relation string) int {
	count := 0
	for _, r := range path {
		if r.Relation == relation {
			count++
		}
	}
	return count
}
