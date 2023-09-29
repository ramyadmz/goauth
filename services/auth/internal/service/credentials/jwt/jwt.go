package jwt

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/ramyadmz/goauth/internal/config"
	cred "github.com/ramyadmz/goauth/internal/service/credentials"
)

// Compile time check for TokenHandler interface satisfaction.
var _ cred.TokenHandler = new(JWTService)

// JWTService manages JSON Web Token operations
type JWTService struct {
	config *config.JWTConfig // JWT configuration
}

// NewJWTService creates a new instance of JWTService
func NewJWTService(cnfg *config.JWTConfig) *JWTService {
	return &JWTService{
		config: cnfg,
	}
}

// GenerateToken generates a new JSON Web Token
// It takes a 'subject' as an input and returns a signed token or an error.
func (js *JWTService) Generate(ctx context.Context, data interface{}) (string, error) {
	strData, ok := data.(string)
	if !ok {
		return "", fmt.Errorf("invalid data type for GenerateToken, expected string")
	}
	// Define the claims for the token
	claims := jwt.StandardClaims{
		Subject:   strData,
		Issuer:    js.config.GetIssuer(),
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Duration(js.config.GetAccessTokenExp()) * time.Minute).Unix(),
	}

	// Create a new JWT token with the claims
	token := jwt.NewWithClaims(js.config.GetSigningMethod(), claims)

	// Sign the token and return it
	signedToken, err := token.SignedString([]byte(js.config.GetSecretKey()))
	if err != nil {
		// Wrap the upper-level error tokenProvider.ErrSigningToken with the specific error
		return "", fmt.Errorf("%w: %w", cred.ErrGeneratingToken, err)
	}

	return signedToken, nil
}

// ValidateToken validates a provided token string.
func (js *JWTService) Validate(ctx context.Context, tokenString string) (interface{}, error) {
	claims := &jwt.StandardClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != js.config.GetSigningMethod() {
			return nil, fmt.Errorf("%w: %v", cred.ErrInvalidSigningMethod, token.Method.Alg())
		}
		return []byte(js.config.GetSecretKey()), nil
	})

	if err != nil {
		return nil, fmt.Errorf("%w: %w", cred.ErrValidatingToken, err)
	}

	if err = token.Claims.Valid(); err != nil {
		return nil, fmt.Errorf("%w: %w", cred.ErrInvalidToken, err)
	}
	return claims.Subject, nil
}

// ValidateToken validates a provided token string.
func (js *JWTService) Invalidate(ctx context.Context, tokenString string) (interface{}, error) {
	// todo: black list the token
	return "", nil
}

// ValidateToken validates a provided token string.
func (js *JWTService) Refresh(ctx context.Context, tokenString string) (string, error) {

	// todo: refresh the token
	return "", nil
}
