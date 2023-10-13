package integration

import "os"

// SetUpLocalTestEnvs set up the required environment variables for local testing
func SetUpLocalTestEnvs() {
	os.Setenv("OAUTH_SERVICENAME", "oauth-app")
	os.Setenv("OAUTH_ENVIRONMENT", "test")

	os.Setenv("OAUTH_POSTGRESQL_HOST", "localhost")
	os.Setenv("OAUTH_POSTGRESQL_PORT", "5432")
	os.Setenv("OAUTH_POSTGRESQL_DATABASE", "oauth-db")
	os.Setenv("OAUTH_POSTGRESQL_USERNAME", "postgres")
	os.Setenv("OAUTH_POSTGRESQL_PASSWORD", "password")
	os.Setenv("OAUTH_POSTGRESQL_SSL", "disable")

	os.Setenv("OAUTH_JWT_SECRET", "verysecretKey")
	os.Setenv("OAUTH_JWT_ISSUER", "oauth")
	os.Setenv("OAUTH_JWT_AUDIENCE", "users")
	os.Setenv("OAUTH_JWT_ALGORITHM", "HS256")
	os.Setenv("OAUTH_JWT_EXPIRATION_TIME", "3600")
	os.Setenv("OAUTH_JWT_REFRESH_EXPIRATION_TIME", "7200")
	os.Setenv("OAUTH_JWT_HEADER_NAME", "Authorization")
	os.Setenv("OAUTH_JWT_HEADER_PREFIX", "Bearer")
}

// UnSetLocalTestEnvs unset up the required environment variables for local testing
func UnSetLocalTestEnvs() {
	os.Unsetenv("OAUTH_SERVICENAME")
	os.Unsetenv("OAUTH_ENVIRONMENT")

	os.Unsetenv("OAUTH_POSTGRESQL_HOST")
	os.Unsetenv("OAUTH_POSTGRESQL_PORT")
	os.Unsetenv("OAUTH_POSTGRESQL_DATABASE")
	os.Unsetenv("OAUTH_POSTGRESQL_USERNAME")
	os.Unsetenv("OAUTH_POSTGRESQL_PASSWORD")
	os.Unsetenv("OAUTH_POSTGRESQL_SSL")

	os.Unsetenv("OAUTH_JWT_SECRET")
	os.Unsetenv("OAUTH_JWT_ISSUER")
	os.Unsetenv("OAUTH_JWT_AUDIENCE")
	os.Unsetenv("OAUTH_JWT_ALGORITHM")
	os.Unsetenv("OAUTH_JWT_EXPIRATION_TIME")
	os.Unsetenv("OAUTH_JWT_REFRESH_EXPIRATION_TIME")
	os.Unsetenv("OAUTH_JWT_HEADER_NAME")
	os.Unsetenv("OAUTH_JWT_HEADER_PREFIX")

}
