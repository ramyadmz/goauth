package jwt

import (
	"context"
	"errors"
	"fmt"
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
	subject := int64(100)

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

	claims := credentials.Claims{
		Subject:   int64(100),
		ExpiresAt: time.Now().Add(1 * time.Minute),
	}

	config, err := config.NewJWTConfig()
	if err != nil {
		t.Fatalf("invalid jwt config: %s", err)
	}

	jwtHandler := NewJWTHandler(config)
	token, err := jwtHandler.Generate(context.Background(), claims, credentials.AccessToken)
	if err != nil {
		t.Fatalf("generating token failed: %s", err)
	}

	res, err := jwtHandler.Validate(context.Background(), token)
	assert.Equal(t, nil, err)
	assert.Equal(t, claims.Subject, res.Subject)
	assert.Equal(t, claims.ExpiresAt.Truncate(time.Second), res.ExpiresAt.Truncate(time.Second))
}

func TestValidate_ExpiredToken(t *testing.T) {
	integration.SetUpLocalTestEnvs()
	defer integration.UnSetLocalTestEnvs()
	os.Setenv("OAUTH_JWT_EXPIRATION_TIME", "2")
	subject := int64(100)

	config, err := config.NewJWTConfig()
	if err != nil {
		t.Fatalf("invalid jwt config: %s", err)
	}

	jwtHandler := NewJWTHandler(config)
	expiredToken, err := jwtHandler.Generate(context.Background(), subject, credentials.AccessToken)
	if err != nil {
		t.Fatalf("generating token failed: %s", err)
	}

	time.Sleep(2 * time.Second)

	_, err = jwtHandler.Validate(context.Background(), expiredToken)
	fmt.Println(err)

	assert.Equal(t, true, errors.Is(err, credentials.ErrInvalidToken))
}
