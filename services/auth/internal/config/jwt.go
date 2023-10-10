// Package config provides functionalities to manage JWT configurations.
package config

import (
	"errors"
	"os"
	"strconv"

	"github.com/golang-jwt/jwt"
)

// JWTConfig holds the JWT configurations.
type JWTConfig struct {
	secretKey       string
	signingMethod   jwt.SigningMethod
	accessTokenExp  int // Expiration time for access token in minutes
	refreshTokenExp int // Expiration time for refresh token in minutes
	issuer          string
}

// JWTConfigBuilder helps in building a JWTConfig object.
type JWTConfigBuilder struct {
	config JWTConfig
}

// NewJWTConfigBuilder returns a new instance of JWTConfigBuilder.
func NewJWTConfigBuilder() *JWTConfigBuilder {
	return &JWTConfigBuilder{}
}

// FromEnv populates the JWTConfig object with values from environment variables.
func (b *JWTConfigBuilder) FromEnv() *JWTConfigBuilder {
	b.config.secretKey = os.Getenv("JWT_SECRET_KEY")
	b.config.signingMethod = jwt.GetSigningMethod(os.Getenv("JWT_SIGNING_METHOD"))
	b.config.accessTokenExp, _ = strconv.Atoi(os.Getenv("JWT_ACCESS_TOKEN_EXP"))
	b.config.refreshTokenExp, _ = strconv.Atoi(os.Getenv("JWT_REFRESH_TOKEN_EXP"))
	b.config.issuer = os.Getenv("JWT_ISSUER")
	return b
}

// Validate checks if the JWTConfig object has valid fields.
func (b *JWTConfigBuilder) Validate() error {
	if b.config.signingMethod == nil {
		return errors.New("SigningMethod is not valid")
	}

	if b.config.secretKey == "" {
		return errors.New("secretKey must not be empty")
	}

	if b.config.accessTokenExp == 0 {
		return errors.New("AccessTokenExp must greater than zero")
	}

	if b.config.refreshTokenExp == 0 {
		return errors.New("RefreshTokenExp must greater than zero")
	}

	if b.config.issuer == "" {
		return errors.New("issuer must not be empty")
	}

	return nil
}

// Build returns a fully built JWTConfig, if it is valid.
func (b *JWTConfigBuilder) Build() (*JWTConfig, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return &b.config, nil
}

// GetSecretKey returns the secret key from the JWTConfig.
func (c *JWTConfig) GetSecretKey() string {
	return c.secretKey
}

// GetSigningMethod returns the signing method from the JWTConfig.
func (c *JWTConfig) GetSigningMethod() jwt.SigningMethod {
	return c.signingMethod
}

// GetIssuer returns the issuer from the JWTConfig.
func (c *JWTConfig) GetIssuer() string {
	return c.issuer
}

// GetAccessTokenExp returns the access token expiration time from the JWTConfig.
func (c *JWTConfig) GetAccessTokenExp() int {
	return c.accessTokenExp
}

// GetRefreshTokenExp returns the refresh token expiration time from the JWTConfig.
func (c *JWTConfig) GetRefreshTokenExp() int {
	return c.refreshTokenExp
}
