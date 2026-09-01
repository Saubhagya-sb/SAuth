# Requires GNU make. On Windows: `winget install ezwinports.make` or run the
# underlying commands from the README directly.

SHELL := /bin/sh
DB_URL ?= postgres://sauth_app:sauth_dev_pw@localhost:5432/sauth?sslmode=disable
MIGRATIONS := migrations

.PHONY: help bootstrap migrate-up migrate-down migrate-force sqlc seed run build test tidy

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n", $$1, $$2}'

bootstrap: ## Create DB, app role, citext extension (needs postgres superuser)
	psql -U postgres -f scripts/bootstrap_db.sql

migrate-up: ## Apply all pending migrations
	migrate -path $(MIGRATIONS) -database "$(DB_URL)" up

migrate-down: ## Roll back the last migration
	migrate -path $(MIGRATIONS) -database "$(DB_URL)" down 1

migrate-force: ## Set migration version without running (usage: make migrate-force V=1)
	migrate -path $(MIGRATIONS) -database "$(DB_URL)" force $(V)

sqlc: ## Regenerate internal/db from query/*.sql
	sqlc generate

seed: ## Insert a dev org/project/default-role (prints the API key)
	go run ./cmd/seed

run: ## Run the API server
	go run ./cmd/server

build: ## Build the API server binary into ./bin
	go build -o bin/server ./cmd/server

test: ## Run tests (set SAUTH_TEST_DATABASE_URL for the integration suite)
	go test ./...

tidy: ## Sync go.mod/go.sum
	go mod tidy
