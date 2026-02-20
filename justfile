set shell := ["bash", "-cu"]

api_dir := "api"

default:
	@just --list

up:
	docker compose up -d postgres

down:
	docker compose down

logs:
	docker compose logs -f postgres

api-run:
	cd {{api_dir}} && go run ./cmd/server

api-build:
	cd {{api_dir}} && mkdir -p bin && go build -o ./bin/server ./cmd/server

air-install:
	go install github.com/air-verse/air@latest

api-air:
	cd {{api_dir}} && air -c air.toml

api-test:
	cd {{api_dir}} && go test ./...

api-seed:
	cd {{api_dir}} && go run ./cmd/seed

api-db-reset:
	cd {{api_dir}} && set -a && source ".env" && set +a && goose -dir sql/schema postgres "$DATABASE_URL" reset && goose -dir sql/schema postgres "$DATABASE_URL" up && go run ./cmd/seed

api-race:
	cd {{api_dir}} && go test -race ./...

api-vet:
	cd {{api_dir}} && go vet ./...

api-tidy:
	cd {{api_dir}} && go mod tidy

api-sqlc:
	cd {{api_dir}} && sqlc generate -f sql/sqlc.yaml

api-goose-up:
	cd {{api_dir}} && goose -dir sql/schema postgres "$DATABASE_URL" up

api-goose-down:
	cd {{api_dir}} && goose -dir sql/schema postgres "$DATABASE_URL" down
