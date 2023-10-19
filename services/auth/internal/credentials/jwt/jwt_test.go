package jwt

import (
	"context"
	"errors"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
	"github.com/ramyadmz/goauth/integration"
	"github.com/ramyadmz/goauth/internal/config"
	"github.com/ramyadmz/goauth/internal/credentials"
)

func TestGenerate_Success(t *testing.T) {
	integration.SetUpLocalTestEnvs()
	defer integration.UnSetLocalTestEnvs()
	subject := rand.Int63()

	config, err := config.NewJWTConfig()
	if err != nil {
		t.Fatalf("invalid jwt config: %s", err)
	}

	jwtHandler := NewJWTHandler(config)
	token, err := jwtHandler.Generate(context.Background(), subject, credentials.AccessToken)
	assert.Equal(t, nil, err)
	assert.NotEqual(t, 0, len(token))
}

func TestGenerate_InvalidClaims(t *testing.T) {
	integration.SetUpLocalTestEnvs()
	defer integration.UnSetLocalTestEnvs()
	subject := int64(0)

	config, err := config.NewJWTConfig()
	if err != nil {
		t.Fatalf("invalid jwt config: %s", err)
	}

	jwtHandler := NewJWTHandler(config)
	_, err = jwtHandler.Generate(context.Background(), subject, credentials.AccessToken)

	assert.NotEqual(t, nil, err)
}

func TestValidate_Success(t *testing.T) {
	integration.SetUpLocalTestEnvs()
	defer integration.UnSetLocalTestEnvs()

	subject := rand.Int63()

	config, err := config.NewJWTConfig()
	if err != nil {
		t.Fatalf("invalid jwt config: %s", err)
	}
	expiresAt := time.Now().Add(config.GetExpirationTime())

	jwtHandler := NewJWTHandler(config)
	token, err := jwtHandler.Generate(context.Background(), subject, credentials.AccessToken)
	if err != nil {
		t.Fatalf("generating token failed: %s", err)
	}

	res, err := jwtHandler.Validate(context.Background(), token)
	assert.Equal(t, nil, err)
	assert.Equal(t, subject, res.Subject)
	assert.Equal(t, expiresAt.Truncate(time.Second), res.ExpiresAt.Truncate(time.Second))
}

func TestValidate_ExpiredToken(t *testing.T) {
	integration.SetUpLocalTestEnvs()
	defer integration.UnSetLocalTestEnvs()
	os.Setenv("OAUTH_JWT_EXPIRATION_TIME", "1")
	subject := rand.Int63()

	config, err := config.NewJWTConfig()
	if err != nil {
		t.Fatalf("invalid jwt config: %s", err)
	}

	jwtHandler := NewJWTHandler(config)
	expiredToken, err := jwtHandler.Generate(context.Background(), subject, credentials.AccessToken)
	if err != nil {
		t.Fatalf("generating token failed: %s", err)
	}

	time.Sleep(1 * time.Second)

	_, err = jwtHandler.Validate(context.Background(), expiredToken)

	assert.Equal(t, true, errors.Is(err, credentials.ErrInvalidToken))
}
