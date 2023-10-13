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

type TokenType int

const (
	AccessToken TokenType = iota
	RefreshToken
)

type JWTClaims struct {
	Subject   int64
	Issuer    string
	IssuedAt  int64
	ExpiresAt int64
}

func (j JWTClaims) Valid() error {
	vErr := new(jwt.ValidationError)
	if j.Subject <= 0 {
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

// GenerateToken generates a new JSON Web Token
// It takes a 'subject' and 'tokenType' as input and returns a signed token or an error.
func (js *JWTHandler) Generate(ctx context.Context, claims cred.Claims) (string, error) {

	//userIDStr := strconv.FormatInt(claims.Subject, 10)
	// Define the claims for the token
	jwtClaims := JWTClaims{
		Subject:   claims.Subject,
		Issuer:    js.config.GetIssuer(),
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: claims.ExpiresAt.Unix(),
	}

	if err := jwtClaims.Valid(); err != nil {
		return "", err
	}

	// Create a new JWT token with the claims
	token := jwt.NewWithClaims(jwt.GetSigningMethod(js.config.GetAlgorithm()), jwtClaims)

	// Sign the token and return it
	signedToken, err := token.SignedString([]byte(js.config.GetSecret()))
	if err != nil {
		// Wrap the upper-level error tokenProvider.ErrSigningToken with the specific error
		return "", fmt.Errorf("%w: %w", cred.ErrGeneratingToken, err)
	}

	return signedToken, nil
}

// ValidateToken validates a provided token string.
func (js *JWTHandler) Validate(ctx context.Context, token string) (*cred.Claims, error) {
	claims := &JWTClaims{}

	jwtToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.GetSigningMethod(js.config.GetAlgorithm()) {
			return nil, fmt.Errorf("%w: %v", cred.ErrInvalidSigningMethod, token.Method.Alg())
		}
		return []byte(js.config.GetSecret()), nil
	})

	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet|jwt.ValidationErrorId) != 0 {
				return nil, cred.ErrInvalidToken
			}
		}
		return nil, cred.ErrValidatingToken
	}

	parsedClaims, ok := jwtToken.Claims.(*JWTClaims)

	if !ok || !jwtToken.Valid {
		return nil, cred.ErrInvalidToken
	}

	return &cred.Claims{
		Subject:   parsedClaims.Subject,
		ExpiresAt: time.Unix(parsedClaims.ExpiresAt, 0),
	}, nil
}

// ValidateToken validates a provided token string.
func (js *JWTHandler) Invalidate(ctx context.Context, tokenString string) error {
	panic("implement me")
}

// ValidateToken validates a provided token string.
func (js *JWTHandler) Refresh(ctx context.Context, tokenString string) (string, error) {
	panic("implement me")
}
