package config

import (
	"fmt"

	"github.com/golang-jwt/jwt"
)

type JWTConfig struct {
	secretKey     string
	signingMethod jwt.SigningMethod
}

type JWTConfigBuilder struct {
	jwtConfig JWTConfig
}

func NewJWTConfigBuilder() *JWTConfigBuilder {
	return &JWTConfigBuilder{
		JWTConfig{
			signingMethod: jwt.SigningMethodHS256},
	}
}

func (b *JWTConfigBuilder) WithSecretKey(secretKey string) *JWTConfigBuilder {
	b.jwtConfig.secretKey = secretKey
	return b
}

func (b *JWTConfigBuilder) WithSigningMethod(method jwt.SigningMethod) *JWTConfigBuilder {
	b.jwtConfig.signingMethod = method
	return b
}

func (b *JWTConfigBuilder) Build() (*JWTConfig, error) {
	if len(b.jwtConfig.secretKey) == 0 {
		return nil, fmt.Errorf("secret key should be set")
	}
	return &b.jwtConfig, nil
}

func (config *JWTConfig) GetSigningMethod() jwt.SigningMethod {
	return config.signingMethod
}
