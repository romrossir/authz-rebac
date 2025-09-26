package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

// Define a private type for context keys
type txKeyType struct{}

var txKey = txKeyType{}

var DB *sql.DB

// Statement defines an interface for common database operations (implemented by *sql.DB and *sql.Tx)
type Statement interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
}

// GetStatement retrieves a Statement from the context.
// If no Statement is found, it returns the global DB connection.
func GetStatement(ctx context.Context) Statement {
	if tx, ok := ctx.Value(txKey).(Statement); ok && tx != nil {
		return tx
	}
	return DB // Default to global DB if no transaction in context
}

// InitDB initializes the database connection.
// It expects database connection details from environment variables:
// DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME, DB_SSLMODE
func Connect(dbHost, dbPort, dbName, dbUser, dbPassword string) {
	dbSSLMode := getEnv("DB_SSLMODE", "disable")

	if dbHost == "" || dbPort == "" || dbName == "" || dbUser == "" || dbPassword == "" {
		log.Fatal("Database environment variables (DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD) are required.")
	}

	if dbSSLMode == "" {
		dbSSLMode = "disable" // Default SSL mode
	}

	// Build connection string
	// - search_path option to use 'authz' schema as default
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s options='-c search_path=authz'",
		dbHost, dbPort, dbUser, dbPassword, dbName, dbSSLMode)

	var err error
	DB, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("db connect error:", err)
	}
	if err = DB.Ping(); err != nil {
		log.Fatal("db ping error:", err)
	}
}

func getEnv(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}

// WithTransaction executes the given function within a database transaction.
// If the function returns an error, the transaction is rolled back.
// Otherwise, the transaction is committed.
// Supports transaction propagation
func WithTransaction(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	// Reuse existing transaction if any
	if _, ok := getTx(ctx); ok {
		return fn(ctx)
	}

	// Create new transaction
	tx, err := DB.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  false,
	})
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		} else if err != nil {
			_ = tx.Rollback()
		}
	}()

	ctx = withTx(ctx, tx)

	err = fn(ctx)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func getTx(ctx context.Context) (*sql.Tx, bool) {
	tx, ok := ctx.Value(txKey).(*sql.Tx)
	return tx, ok
}

func withTx(ctx context.Context, tx *sql.Tx) context.Context {
	return context.WithValue(ctx, txKey, tx)
}
