package credentials

import (
	"context"
	"errors"
	"time"
)

var (
	ErrGeneratingSecret     = errors.New("error failed tp generate the secret")
	ErrGeneratingToken      = errors.New("error failed tp generate the token")
	ErrValidatingToken      = errors.New("error failed to parse the token")
	ErrInvalidToken         = errors.New("error token is invalid/expired")
	ErrInvalidSigningMethod = errors.New("unexpected signing method")
)

type Claims struct {
	Subject   int64
	ExpiresAt time.Time
}

type TokenHandler interface {
	Generate(ctx context.Context, claims Claims) (string, error)
	Validate(ctx context.Context, token string) (*Claims, error)
	Invalidate(ctx context.Context, token string) error
}
