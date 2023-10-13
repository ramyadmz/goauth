package config

import (
	"errors"
	"os"
	"strconv"
)

const (
	DefaultHost     = "localhost"
	DefaultPort     = 5432
	DefaultUsername = "postgres"
	DefaultDatabase = "mydatabase"
	DefaultSSLMode  = "disable"
)

// PostgresConfig holds the PostgreSQL database configurations.
type PostgresConfig struct {
	host     string
	port     int
	user     string
	password string
	database string
	sslMode  string
}

// NewPostgresConfig returns a new instance of PostgresConfig and
// loads its values from environment variables or provides defaults.
func NewPostgresConfig() (*PostgresConfig, error) {
	config := &PostgresConfig{
		host:     DefaultHost,
		port:     DefaultPort,
		user:     DefaultUsername,
		database: DefaultDatabase,
		sslMode:  DefaultSSLMode,
	}

	// Load values from environment variables or use defaults
	host := os.Getenv("OAUTH_POSTGRESQL_HOST")
	if len(host) > 0 {
		config.host = host
	}

	portStr := os.Getenv("OAUTH_POSTGRESQL_PORT")
	if len(portStr) > 0 {
		port, err := strconv.Atoi(portStr)
		if err == nil {
			config.port = port
		}
	}

	user := os.Getenv("OAUTH_POSTGRESQL_USERNAME")
	if len(user) > 0 {
		config.user = user
	}

	password := os.Getenv("OAUTH_POSTGRESQL_PASSWORD")
	if len(password) == 0 {
		return nil, errors.New("PG_PASSWORD environment variable is required")
	}
	config.password = password

	database := os.Getenv("OAUTH_POSTGRESQL_DATABASE")
	if len(database) > 0 {
		config.database = database
	}

	sslMode := os.Getenv("OAUTH_POSTGRESQL_SSL")
	if len(sslMode) > 0 {
		config.sslMode = sslMode
	}

	return config, nil
}

// GetHost returns the PostgreSQL server host.
func (c *PostgresConfig) GetHost() string {
	return c.host
}

// GetPort returns the PostgreSQL server port.
func (c *PostgresConfig) GetPort() int {
	return c.port
}

// GetUser returns the PostgreSQL username.
func (c *PostgresConfig) GetUser() string {
	return c.user
}

// GetPassword returns the PostgreSQL password.
func (c *PostgresConfig) GetPassword() string {
	return c.password
}

// GetDatabase returns the PostgreSQL database name.
func (c *PostgresConfig) GetDatabase() string {
	return c.database
}

// GetSSLMode returns the PostgreSQL SSL mode.
func (c *PostgresConfig) GetSSLMode() string {
	return c.sslMode
}
