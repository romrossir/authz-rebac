package authz

import (
	_ "embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed schema.yaml
var Schema []byte

// LoadMetadata loads the schema metadata on startup and panics if schema loading fails.
func LoadMetadata() Metadata {
	var meta Metadata
	if err := yaml.Unmarshal(Schema, &meta); err != nil {
		panic(fmt.Sprintf("failed to load authz metadata: %v", err))
	}
	return meta
}

// Metadata represents the authorization schema, including version and object definitions.
type Metadata struct {
	SchemaVersion string                      `yaml:"schema_version"`
	Objects       map[string]ObjectDefinition `yaml:"objects"`
}

// ObjectDefinition defines the relations and permissions for a given object type.
type ObjectDefinition struct {
	Relations       map[string]RelationDefinition   `yaml:"relations"`
	Permissions     map[string]PermissionDefinition `yaml:"permissions"`
	PrecedenceRules []PrecedenceRule                `yaml:"precedence_rules"`
}

// RelationDefinition defines the allowed subject types for a specific relation.
type RelationDefinition struct {
	SubjectTypes []string `yaml:"subject_types"`
}

// PermissionDefinition defines how a permission is composed, including inclusions (AnyOf) and exclusions (Except).
type PermissionDefinition struct {
	AnyOf  []string `yaml:"any_of"`
	Except []string `yaml:"except"`
}

// PrecedenceRule defines how to rank traversal paths when multiple valid paths exist between a subject and a resource.
// Rules are applied in order, and the first rule that differentiates two paths determines which path is more effective.
// Supported rules:
//   - "path_with": prefer paths that contain the given relation.
//   - "path_without": prefer paths that do NOT contain the given relation.
//   - "path_with_fewer": prefer paths that contain fewer occurrences of the given relation (e.g., closer in hierarchy).
type PrecedenceRule struct {
	Rule     string
	Relation string
}

// IsValidObject checks that the object is non-empty and its type exists in metadata.
func (m Metadata) IsValidObject(obj Object) error {
	if obj.Type == "" {
		return fmt.Errorf("type is required")
	}
	if obj.ID == "" {
		return fmt.Errorf("id is required")
	}
	if _, ok := m.Objects[obj.Type]; !ok {
		return fmt.Errorf("type is invalid: %q", obj.Type)
	}
	return nil
}

// IsValidObject checks that the object is non-empty and its type exists in metadata.
func (m Metadata) IsValidObjectType(obj Object) error {
	if obj.Type == "" {
		return fmt.Errorf("type is required")
	}
	if _, ok := m.Objects[obj.Type]; !ok {
		return fmt.Errorf("type is invalid: %q", obj.Type)
	}
	return nil
}

// IsValidRelation checks that the relation exists on the resource type
// and that the subject’s type is allowed by the relation definition.
func (m Metadata) IsValidRelation(rel Relationship) error {
	if err := m.IsValidObject(rel.Resource); err != nil {
		return fmt.Errorf("resource %w", err)
	}
	if err := m.IsValidObject(rel.Subject); err != nil {
		return fmt.Errorf("subject %w", err)
	}
	if rel.Relation == "" {
		return fmt.Errorf("relation is required")
	}

	// Verify relation exists for the resource type
	relDef, ok := m.Objects[rel.Resource.Type].Relations[rel.Relation]
	if !ok {
		return fmt.Errorf("relation is invalid: %s->%s->%s", rel.Resource.Type, rel.Relation, rel.Subject.Type)
	}

	// Check if subject type is allowed
	allowed := false
	for _, t := range relDef.SubjectTypes {
		if t == rel.Subject.Type {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("relation is invalid: %s->%s->%s", rel.Resource.Type, rel.Relation, rel.Subject.Type)
	}

	return nil
}

// IsValidPermission checks that the permission exists on the object type.
func (m Metadata) IsValidPermission(obj Object, permission string) error {
	if err := m.IsValidObject(obj); err != nil {
		return err
	}
	objDef, ok := m.Objects[obj.Type]
	if !ok {
		return fmt.Errorf("unknown object type: %q", obj.Type)
	}
	if _, ok := objDef.Permissions[permission]; !ok {
		return fmt.Errorf("permission %q is invalid for resource type %q", permission, obj.Type)
	}
	return nil
}
