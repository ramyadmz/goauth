# Define variables for your PostgreSQL connection details using environment variables
PG_USER := $(shell echo $$OAUTH_POSTGRESQL_USERNAME)
PG_PASSWORD := $(shell echo $$OAUTH_POSTGRESQL_PASSWORD)
PG_HOST := $(shell echo $$OAUTH_POSTGRESQL_HOST)
PG_PORT := $(shell echo $$OAUTH_POSTGRESQL_PORT)
PG_DATABASE := $(shell echo $$OAUTH_POSTGRESQL_DATABASE)
PG_SSL_MODE := $(shell echo $$OAUTH_POSTGRESQL_SSL)

# Define your migration commands using the environment variables
MIGRATE_UP_CMD := migrate -path /app/internal/data/migration -database "postgresql://$(PG_USER):$(PG_PASSWORD)@$(PG_HOST):$(PG_PORT)/$(PG_DATABASE)?sslmode=$(PG_SSL_MODE)" up
MIGRATE_DOWN_CMD := migrate -path /app/internal/data/migration -database "postgresql://$(PG_USER):$(PG_PASSWORD)@$(PG_HOST):$(PG_PORT)/$(PG_DATABASE)?sslmode=$(PG_SSL_MODE)" down -all

migrate-up:
	$(MIGRATE_UP_CMD)

migrate-down:
	$(MIGRATE_DOWN_CMD)

test:
	ginkgo -v

test-with-migrations: migrate-up test migrate-down
