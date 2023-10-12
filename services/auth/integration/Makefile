migrate-up:
	migrate -path /app/internal/data/migration -database "postgresql://postgres:password@auth-db:5432/auth?sslmode=disable" up

migrate-down:
	migrate -path /app/internal/data/migration -database "postgresql://postgres:password@auth-db:5432/auth?sslmode=disable" down -all

test:
	ginkgo -v

test-with-migrations: migrate-up test migrate-down
