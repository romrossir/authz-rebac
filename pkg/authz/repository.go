package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lib/pq"
	"github.com/romrossi/authz-rebac/pkg/db"
)

// AuthzRepository defines the interface for authorization-related database operations.
type AuthzRepository interface {
	InsertBulk(ctx context.Context, relationship []Relationship) error
	DeleteBulk(ctx context.Context, relationship []Relationship) error
	ListPaths(ctx context.Context, request TraversalRequest) ([]TraversalResponseItem, error)
}

// pgRepository is a PostgreSQL implementation of the authz repository.
type pgRepository struct{}

// NewPGRepository creates a new pgRepository instance.
func NewPGRepository() AuthzRepository {
	return &pgRepository{}
}

// InsertBulk inserts multiple relationships into the database in one query.
func (r *pgRepository) InsertBulk(ctx context.Context, relationships []Relationship) error {
	if len(relationships) == 0 {
		return nil // nothing to insert
	}

	// Build query dynamically
	query := `
        INSERT INTO relationship (resource_id, resource_type, subject_id, subject_type, relation)
        VALUES 
    `

	// placeholders for each row: ($1, $2, $3, $4, $5), ($6, $7, $8, $9, $10), ...
	values := make([]interface{}, 0, len(relationships)*5)
	placeholders := make([]string, 0, len(relationships))

	for i, rel := range relationships {
		n := i*5 + 1
		placeholders = append(placeholders,
			fmt.Sprintf("($%d, $%d, $%d, $%d, $%d)", n, n+1, n+2, n+3, n+4),
		)
		values = append(values,
			rel.Resource.ID,
			rel.Resource.Type,
			rel.Subject.ID,
			rel.Subject.Type,
			rel.Relation,
		)
	}

	query += strings.Join(placeholders, ",")
	query += " ON CONFLICT DO NOTHING"

	_, err := db.GetStatement(ctx).ExecContext(ctx, query, values...)
	if err != nil {
		return fmt.Errorf("bulk insert relationships failed: %w", err)
	}
	return nil
}

// DeleteBulk removes multiple relationships from the database in one query.
func (r *pgRepository) DeleteBulk(ctx context.Context, relationships []Relationship) error {
	if len(relationships) == 0 {
		return nil // nothing to delete
	}

	query := `
        DELETE FROM relationship
        WHERE (resource_id, resource_type, subject_id, subject_type, relation) IN (
    `

	placeholders := make([]string, 0, len(relationships))
	values := make([]interface{}, 0, len(relationships)*5)

	for i, rel := range relationships {
		n := i*5 + 1
		placeholders = append(placeholders,
			fmt.Sprintf("($%d, $%d, $%d, $%d, $%d)", n, n+1, n+2, n+3, n+4),
		)
		values = append(values,
			rel.Resource.ID,
			rel.Resource.Type,
			rel.Subject.ID,
			rel.Subject.Type,
			rel.Relation,
		)
	}

	query += strings.Join(placeholders, ",") + ")"

	_, err := db.GetStatement(ctx).ExecContext(ctx, query, values...)
	if err != nil {
		return fmt.Errorf("bulk delete relationships failed: %w", err)
	}
	return nil
}

// ListPaths performs a recursive traversal and returns relationship paths.
func (r *pgRepository) ListPaths(ctx context.Context, tRequest TraversalRequest) ([]TraversalResponseItem, error) {
	// SQL request template
	const sqlTemplate = `
		WITH RECURSIVE rel_tree AS (
			-- Start node
			SELECT
				r.%[1]s_type AS start_type,
				r.%[1]s_id   AS start_id,
				r.%[2]s_type AS next_type,
				r.%[2]s_id   AS next_id,
				json_build_array(
					json_build_object(
						'resource', r.resource_type || ':' || r.resource_id,
						'subject', r.subject_type || ':' || r.subject_id,
						'relation', r.relation
					)
				)::jsonb AS path
			FROM relationship r
			WHERE r.%[1]s_type = $1 AND r.%[1]s_id = $2

			UNION ALL

			-- Recursive step
			SELECT
				t.start_type,
				t.start_id,
				r.%[2]s_type AS next_type,
				r.%[2]s_id   AS next_id,
				t.path || json_build_object(
					'resource', r.resource_type || ':' || r.resource_id,
					'subject', r.subject_type || ':' || r.subject_id,
					'relation', r.relation
				)::jsonb
			FROM relationship r
			JOIN rel_tree t
			ON r.%[1]s_id = t.next_id
			AND r.%[1]s_type = t.next_type
			WHERE ($3::text[] IS NULL OR NOT (t.next_type = ANY($3::text[])))
		)
		SELECT
			start_type,
			start_id,
			next_type,
			next_id,
			json_agg(path)
		FROM rel_tree
		WHERE (($4 = '' AND $5 = '') OR (next_type = $4 AND next_id = $5))
		AND ($3::text[] IS NULL OR next_type = ANY($3::text[]))
		GROUP BY start_type, start_id, next_type, next_id
	`

	// Prepare query depending on traversal direction
	var query string
	if tRequest.Forward {
		query = fmt.Sprintf(sqlTemplate, "resource", "subject")
	} else {
		query = fmt.Sprintf(sqlTemplate, "subject", "resource")
	}

	// Prepare args
	args := []any{tRequest.StartOn.Type, tRequest.StartOn.ID, pq.Array(tRequest.StopOnTypes)}
	stopType, stopID := "", ""
	if tRequest.StopOn != nil {
		stopType = tRequest.StopOn.Type
		stopID = tRequest.StopOn.ID
	}
	args = append(args, stopType, stopID)

	// Execute query
	// start := time.Now()
	rows, err := db.GetStatement(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	// duration := time.Since(start)
	// log.Printf("Query executed in %v", duration)
	defer rows.Close()

	// Build response
	response := make([]TraversalResponseItem, 0)
	for rows.Next() {
		var start, stop Object
		var rawPaths []byte
		if err := rows.Scan(&start.Type, &start.ID, &stop.Type, &stop.ID, &rawPaths); err != nil {
			return nil, fmt.Errorf("scan traversal row failed: %w", err)
		}

		var paths [][]Relationship
		if err := json.Unmarshal(rawPaths, &paths); err != nil {
			return nil, err
		}

		var resource, subject Object
		if tRequest.Forward {
			resource = start
			subject = stop
		} else {
			resource = stop
			subject = start
		}

		response = append(response, TraversalResponseItem{
			Resource: resource,
			Subject:  subject,
			Paths:    paths,
		})
	}

	return response, rows.Err()
}
