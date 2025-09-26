package authz

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Object represents a unique resource or subject
type Object struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// MarshalJSON serializes the object as a compact "type:id" string.
func (o Object) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.Type + ":" + o.ID)
}

// UnmarshalJSON deserializes a "type:id" string into an Object struct.
func (o *Object) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid object format: %q", s)
	}

	o.Type = parts[0]
	o.ID = parts[1]

	return nil
}

// Relationship represents a relationship entry,
// associating a subject with a relation on a resource object.
type Relationship struct {
	Resource Object `json:"resource"`
	Subject  Object `json:"subject"`
	Relation string `json:"relation"`
}

// TraversalRequest defines parameters for traversing relationship paths in the graph.
type TraversalRequest struct {
	// StartOn is the starting object for traversal.
	StartOn Object

	// Forward indicates the traversal direction.
	// true: follow natural direction (resource → subject)
	// false: traverse against relation direction (subject → resource)
	Forward bool

	// StopOnTypes specifies node types at which traversal should stop.
	// All paths ending at nodes of these types will be returned.
	StopOnTypes []string

	// StopOn specifies an exact node to stop traversal.
	// Only paths reaching this specific node will be returned.
	StopOn *Object
}

// TraversalResponseItem contains all discovered paths for a specific resource-subject pair.
type TraversalResponseItem struct {
	// Paths holds all discovered relationship paths.
	Paths [][]Relationship `json:"paths"`

	// Resource is the resource object of this traversal item.
	Resource Object `json:"resource"`

	// Subject is the subject object reached at the end of paths.
	Subject Object `json:"subject"`
}

// PermissionCheckItem represents the evaluation of permissions for a resource-subject pair.
type PermissionCheckItem struct {
	Resource        Object                    `json:"resource"`
	Subject         Object                    `json:"subject"`
	PermissionEvals map[string]PermissionEval `json:"permissions"` // key: permission name
}

// PermissionEval represents the result of evaluating a single permission.
type PermissionEval struct {
	Allowed       bool             `json:"allowed"`                  // true if permission is granted
	MatchingPaths [][]Relationship `json:"matching_paths,omitempty"` // paths satisfying the permission
}
