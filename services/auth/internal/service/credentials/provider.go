package credentials

import "errors"

var (
	ErrGeneratingToken      = errors.New("Error failed tp generate the token")
	ErrValidatingToken      = errors.New("Error failed to parse the token")
	ErrInvalidToken         = errors.New("Error token is invalid/expired")
	ErrInvalidSigningMethod = errors.New("Unexpected signing method")
)

type TokenHandler interface {
	Generate(data interface{}) (string, error)
	Validate(key string) (interface{}, error)
	Invalidate(key string) (interface{}, error)
	Refresh(key string) (string, error)
}
