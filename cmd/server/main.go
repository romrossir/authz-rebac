package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/romrossi/authz-rebac/pkg/authz"
	"github.com/romrossi/authz-rebac/pkg/db"
	"github.com/romrossi/authz-rebac/pkg/router"
)

func main() {
	// Args
	var dbHost string
	var dbPort string
	var dbName string
	var dbUser string
	var dbPassword string
	flag.StringVar(&dbHost, "db-host", envOrDefault("DB_HOST", "localhost"), "Hostname for the database")
	flag.StringVar(&dbPort, "db-port", envOrDefault("DB_PORT", "5432"), "Port for the database")
	flag.StringVar(&dbName, "db-name", envOrDefault("DB_NAME", "postgres"), "Name for the database")
	flag.StringVar(&dbUser, "db-user", envOrDefault("DB_USER", "postgres"), "User for the database")
	flag.StringVar(&dbPassword, "db-password", envOrDefault("DB_PASSWORD", "mochigome"), "Password for the database")
	flag.Parse()

	// Setup DB connection
	db.Connect(dbHost, dbPort, dbName, dbUser, dbPassword)

	// Initialize Authz metadata, repo, service, handler
	meta := authz.LoadMetadata()
	authzRepo := authz.NewPGRepository()
	authzService := authz.NewService(authzRepo, meta)
	authzHandler := authz.NewAuthzHandler(authzService, meta)

	// Initialize HTTP router
	v1Prefix := "/api/v1"
	r := router.NewRouter()

	// Register routes
	r.Handle("GET", v1Prefix+"/permissions/{permission}", authzHandler.CheckPermission())
	r.Handle("GET", v1Prefix+"/permissions", authzHandler.CheckPermissions())
	r.Handle("GET", v1Prefix+"/resources/{resource}/relations", authzHandler.ListResourceRelations())
	r.Handle("POST", v1Prefix+"/relations", authzHandler.ManageRelationships())

	// Start HTTP server
	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

// envOrDefault checks for an environment variable, and if not found, uses a default value.
func envOrDefault(envKey, defaultVal string) string {
	if val, exists := os.LookupEnv(envKey); exists {
		return val
	}
	return defaultVal
}
