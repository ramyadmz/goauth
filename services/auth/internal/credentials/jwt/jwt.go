package jwt

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/ramyadmz/goauth/internal/config"
	cred "github.com/ramyadmz/goauth/internal/credentials"
)

// Compile time check for TokenHandler interface satisfaction.
var _ cred.TokenHandler = new(JWTHandler)

// JWTHandler manages JSON Web Token operations
type JWTHandler struct {
	config *config.JWTConfig // JWT configuration
}

// NewJWTHandler creates a new instance of JWTHandler
func NewJWTHandler(cnfg *config.JWTConfig) *JWTHandler {
	return &JWTHandler{
		config: cnfg,
	}
}

type JWTClaims struct {
	UserID    int64
	Issuer    string
	IssuedAt  int64
	ExpiresAt int64
}

// Valid validates the JWT claims.
func (j JWTClaims) Valid() error {
	vErr := new(jwt.ValidationError)
	if j.UserID <= 0 {
		vErr.Errors |= jwt.ValidationErrorId
	}

	if j.IssuedAt > time.Now().Unix() {
		vErr.Errors |= jwt.ValidationErrorIssuedAt
	}

	if j.ExpiresAt <= time.Now().Unix() {
		vErr.Errors |= jwt.ValidationErrorExpired
	}

	if vErr.Errors > 0 {
		vErr.Inner = cred.ErrInvalidClaims
		return vErr
	}

	return nil
}

// Generate takes a 'subject' and 'tokenType' as input and generates a new JSON Web Token
func (j *JWTHandler) Generate(ctx context.Context, subject interface{}, tokenType cred.TokenType) (string, error) {
	var expirationTime time.Duration

	switch tokenType {
	case cred.AccessToken:
		expirationTime = j.config.GetExpirationTime()
	case cred.RefreshToken:
		expirationTime = j.config.GetRefreshExpirationTime()
	default:
		return "", fmt.Errorf("invalid token type: %v", tokenType)
	}

	// Define the claims for the token
	jwtClaims := JWTClaims{
		UserID:    subject.(int64),
		Issuer:    j.config.GetIssuer(),
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: jwt.TimeFunc().Add(expirationTime).Unix(),
	}

	if err := jwtClaims.Valid(); err != nil {
		return "", err
	}

	// Create a new JWT token with the claims
	token := jwt.NewWithClaims(jwt.GetSigningMethod(j.config.GetAlgorithm()), jwtClaims)

	// Sign the token and return it
	signedToken, err := token.SignedString([]byte(j.config.GetSecret()))
	if err != nil {
		return "", fmt.Errorf("%w: %w", cred.ErrGenerateToken, err)
	}

	return signedToken, nil
}

// Validate validates a provided token string.
func (js *JWTHandler) Validate(ctx context.Context, token string) (*cred.Claims, error) {
	claims := &JWTClaims{}

	jwtToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.GetSigningMethod(js.config.GetAlgorithm()) {
			return nil, fmt.Errorf("%w: %v", cred.ErrSigningMethod, token.Method.Alg())
		}
		return []byte(js.config.GetSecret()), nil
	})

	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet|jwt.ValidationErrorId) != 0 {
				return nil, cred.ErrInvalidToken
			}
		}
		return nil, cred.ErrValidateToken
	}

	parsedClaims, ok := jwtToken.Claims.(*JWTClaims)

	if !ok || !jwtToken.Valid {
		return nil, cred.ErrInvalidToken
	}

	return &cred.Claims{
		Subject:   parsedClaims.UserID,
		ExpiresAt: time.Unix(parsedClaims.ExpiresAt, 0),
	}, nil
}

// InvalidateToken validates a provided token string.
func (js *JWTHandler) Invalidate(ctx context.Context, tokenString string) error {
	panic("implement me")
}
