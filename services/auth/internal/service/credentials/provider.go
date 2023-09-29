package credentials

import (
	"context"
	"errors"
)

var (
	ErrGeneratingToken      = errors.New("Error failed tp generate the token")
	ErrValidatingToken      = errors.New("Error failed to parse the token")
	ErrInvalidToken         = errors.New("Error token is invalid/expired")
	ErrInvalidSigningMethod = errors.New("Unexpected signing method")
)

type TokenHandler interface {
	Generate(ctx context.Context, data interface{}) (string, error)
	Validate(ctx context.Context, key string) (interface{}, error)
	Invalidate(ctx context.Context, key string) (interface{}, error)
	Refresh(ctx context.Context, key string) (string, error)
}
