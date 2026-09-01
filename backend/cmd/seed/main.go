// Command seed inserts a development organization, project, and default role
// so the end-user auth API has a tenant to work against. Safe to re-run.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/saubhagyabhadhouria/sauth/internal/config"
	"github.com/saubhagyabhadhouria/sauth/internal/database"
	"github.com/saubhagyabhadhouria/sauth/internal/password"
)

const (
	orgID     = "11111111-1111-1111-1111-111111111111"
	projectID = "22222222-2222-2222-2222-222222222222"
	roleID    = "33333333-3333-3333-3333-333333333333"
	apiKey    = "pk_test_dev"
	apiSecret = "sk_test_dev_secret_change_me"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := database.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	secretHash, err := password.Hash(apiSecret)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO organizations (id, name) VALUES ($1, 'Dev Org')
		 ON CONFLICT (id) DO NOTHING`, orgID); err != nil {
		log.Fatal(err)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO projects (id, org_id, name, environment, api_key, api_secret_hash, otp_enabled)
		 VALUES ($1, $2, 'Dev App', 'test', $3, $4, true)
		 ON CONFLICT (id) DO UPDATE SET api_secret_hash = EXCLUDED.api_secret_hash`,
		projectID, orgID, apiKey, secretHash); err != nil {
		log.Fatal(err)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO roles (id, project_id, name, description, is_default)
		 VALUES ($1, $2, 'member', 'Default role for new users', true)
		 ON CONFLICT (id) DO NOTHING`, roleID, projectID); err != nil {
		log.Fatal(err)
	}

	fmt.Println("seed complete")
	fmt.Println("  project id:  " + projectID)
	fmt.Println("  X-API-Key:   " + apiKey)
	fmt.Println("  X-API-Secret:" + apiSecret + "  (server stores only the hash)")
}
