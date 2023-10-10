package jwt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
	"github.com/ramyadmz/goauth/internal/config"
	"github.com/ramyadmz/goauth/internal/service/credentials"
)

func TestGenerate_Success(t *testing.T) {
	setEnvConfigs()
	defer unsetEnvConfigs()

	claims := credentials.Claims{
		Subject:   100,
		ExpiresAt: time.Now().Add(1 * time.Minute),
	}

	config, err := config.NewJWTConfigBuilder().FromEnv().Build()
	if err != nil {
		t.Fatalf("invalid jwt config: %s", err)
	}

	jwtHandler := NewJWTService(config)
	token, err := jwtHandler.Generate(context.Background(), claims)
	assert.Equal(t, nil, err)
	assert.NotEqual(t, 0, len(token))
}

func TestGenerate_InvalidClaims(t *testing.T) {
	setEnvConfigs()
	defer unsetEnvConfigs()
	claims := credentials.Claims{
		Subject:   100,
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}

	config, err := config.NewJWTConfigBuilder().FromEnv().Build()
	if err != nil {
		t.Fatalf("invalid jwt config: %s", err)
	}

	jwtHandler := NewJWTService(config)
	_, err = jwtHandler.Generate(context.Background(), claims)

	assert.Equal(t, true, errors.Is(err, credentials.ErrInvalidClaims))
}

func TestValidate_Success(t *testing.T) {
	setEnvConfigs()
	defer unsetEnvConfigs()

	claims := credentials.Claims{
		Subject:   100,
		ExpiresAt: time.Now().Add(1 * time.Minute),
	}

	config, err := config.NewJWTConfigBuilder().FromEnv().Build()
	if err != nil {
		t.Fatalf("invalid jwt config: %s", err)
	}

	jwtHandler := NewJWTService(config)
	token, err := jwtHandler.Generate(context.Background(), claims)
	if err != nil {
		t.Fatalf("generating token failed: %s", err)
	}

	res, err := jwtHandler.Validate(context.Background(), token)
	assert.Equal(t, nil, err)
	assert.Equal(t, claims.Subject, res.Subject)
	assert.Equal(t, claims.ExpiresAt.Truncate(time.Second), res.ExpiresAt.Truncate(time.Second))
}

func TestValidate_ExpiredToken(t *testing.T) {
	setEnvConfigs()
	defer unsetEnvConfigs()

	claims := credentials.Claims{
		Subject:   100,
		ExpiresAt: time.Now().Add(1 * time.Second),
	}

	config, err := config.NewJWTConfigBuilder().FromEnv().Build()
	if err != nil {
		t.Fatalf("invalid jwt config: %s", err)
	}

	jwtHandler := NewJWTService(config)
	expiredToken, err := jwtHandler.Generate(context.Background(), claims)
	if err != nil {
		t.Fatalf("generating token failed: %s", err)
	}

	time.Sleep(1 * time.Second)

	_, err = jwtHandler.Validate(context.Background(), expiredToken)
	fmt.Println(err)

	assert.Equal(t, true, errors.Is(err, credentials.ErrInvalidToken))
}

func setEnvConfigs() {
	os.Setenv("JWT_SECRET_KEY", "testSecretKey")
	os.Setenv("JWT_SIGNING_METHOD", "HS256")
	os.Setenv("JWT_ACCESS_TOKEN_EXP", "3600")
	os.Setenv("JWT_REFRESH_TOKEN_EXP", "7200")
	os.Setenv("JWT_ISSUER", "yourIssuerHere")
}

func unsetEnvConfigs() {
	os.Unsetenv("JWT_SECRET_KEY")
	os.Unsetenv("JWT_SIGNING_METHOD")
	os.Unsetenv("JWT_ACCESS_TOKEN_EXP")
	os.Unsetenv("JWT_REFRESH_TOKEN_EXP")
	os.Unsetenv("JWT_ISSUER")
}
