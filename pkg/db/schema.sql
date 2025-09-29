-- schema.sql
DROP SCHEMA IF EXISTS authz CASCADE;
CREATE SCHEMA IF NOT EXISTS authz;

-- authz.relationship
CREATE TABLE IF NOT EXISTS authz.relationship (
    resource_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    relation TEXT NOT NULL,
    UNIQUE (resource_id, resource_type, subject_id, subject_type, relation)
);
CREATE INDEX IF NOT EXISTS idx_relationship_subject ON authz.relationship(subject_type, subject_id);
CREATE INDEX IF NOT EXISTS idx_relationship_resource ON authz.relationship(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_relationship_subject_type ON authz.relationship(subject_type);
CREATE INDEX IF NOT EXISTS idx_relationship_resource_type ON authz.relationship(resource_type);
