package config

import (
	"errors"
	"os"
	"strconv"
	"time"
)

const (
	DefaultAlgorithm    = "HS256"
	DefaultHeaderName   = "Authorization"
	DefaultHeaderPrefix = "Bearer"
)

// JWTConfig holds the JWT configurations.
type JWTConfig struct {
	secret                string
	issuer                string
	audience              string
	algorithm             string
	expirationTime        time.Duration
	refreshExpirationTime time.Duration
	headerName            string
	headerPrefix          string
}

// NewJWTConfigBuilder returns a new instance of JWTConfigBuilder and
// loads its values from environment variables or provides defaults.
func NewJWTConfig() (*JWTConfig, error) {
	config := &JWTConfig{
		algorithm:    DefaultAlgorithm,
		headerName:   DefaultHeaderName,
		headerPrefix: DefaultHeaderPrefix,
	}

	if algorithm := os.Getenv("OAUTH_JWT_ALGORITHM"); len(algorithm) > 0 {
		config.algorithm = algorithm
	}

	if headerName := os.Getenv("OAUTH_JWT_HEADER_NAME"); len(headerName) > 0 {
		config.headerName = headerName
	}

	if headerPrefix := os.Getenv("OAUTH_JWT_HEADER_PREFIX"); len(headerPrefix) > 0 {
		config.headerPrefix = headerPrefix
	}

	secret := os.Getenv("OAUTH_JWT_SECRET")
	if len(secret) == 0 {
		return nil, errors.New("OAUTH_JWT_SECRET environment variable is required")
	}
	config.secret = secret

	issuer := os.Getenv("OAUTH_JWT_ISSUER")
	if len(issuer) == 0 {
		return nil, errors.New("OAUTH_JWT_ISSUER environment variable is required")
	}
	config.issuer = issuer

	audience := os.Getenv("OAUTH_JWT_AUDIENCE")
	if len(audience) == 0 {
		return nil, errors.New("OAUTH_JWT_AUDIENCE environment variable is required")
	}
	config.audience = audience

	expTime, err := strconv.Atoi(os.Getenv("OAUTH_JWT_EXPIRATION_TIME"))
	if err != nil || expTime <= 0 {
		return nil, errors.New("OAUTH_JWT_EXPIRATION_TIME environment variable is not valid")
	}
	config.expirationTime = time.Duration(expTime) * time.Second

	refreshExpTime, err := strconv.Atoi(os.Getenv("OAUTH_JWT_REFRESH_EXPIRATION_TIME"))
	if err != nil || refreshExpTime <= 0 {
		return nil, errors.New("OAUTH_JWT_REFRESH_EXPIRATION_TIME environment variable is not valid")
	}
	config.refreshExpirationTime = time.Duration(refreshExpTime) * time.Second

	return config, nil
}

func (c JWTConfig) GetSecret() string                       { return c.secret }
func (c JWTConfig) GetIssuer() string                       { return c.issuer }
func (c JWTConfig) GetAudience() string                     { return c.audience }
func (c JWTConfig) GetAlgorithm() string                    { return c.algorithm }
func (c JWTConfig) GetExpirationTime() time.Duration        { return c.expirationTime }
func (c JWTConfig) GetRefreshExpirationTime() time.Duration { return c.refreshExpirationTime }
func (c JWTConfig) GetHeaderName() string                   { return c.headerName }
func (c JWTConfig) GetHeaderPrefix() string                 { return c.headerPrefix }
