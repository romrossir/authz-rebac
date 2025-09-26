package authz

// Metadata represents the authorization schema, including version and object definitions.
type Metadata struct {
	SchemaVersion string                      `yaml:"schema_version"`
	Objects       map[string]ObjectDefinition `yaml:"objects"`
}

// ObjectDefinition defines the relations and permissions for a given object type.
type ObjectDefinition struct {
	Relations   map[string]RelationDefinition   `yaml:"relations"`
	Permissions map[string]PermissionDefinition `yaml:"permissions"`
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
