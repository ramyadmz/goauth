package token

import "errors"

var (
	ErrSigningToken         = errors.New("Error failed tp sign the token")
	ErrValidatingToken      = errors.New("Error failed to parse the token")
	ErrInvalidToken         = errors.New("Error token has invalid claims")
	ErrInvalidSigningMethod = errors.New("Unexpected signing method")
)

type TokenHandler interface {
	GenerateToken(data interface{}) (string, error)
	ValidateToken(token string) (interface{}, error)
}
