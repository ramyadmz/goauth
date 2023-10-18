package credentials

import (
	"context"
	"errors"
	"time"
)

// Define error messages for various scenarios
var (
	// General errors
	ErrGenerateSecret = errors.New("failed to generate secret")
	ErrInvalidClaims  = errors.New("invalid claims")

	// Token-related errors
	ErrGenerateToken = errors.New("failed to generate token")
	ErrValidateToken = errors.New("failed to validate token")
	ErrInvalidToken  = errors.New("token is invalid or expired")
	ErrSigningMethod = errors.New("unexpected signing method")

	// Session-related errors
	ErrStartSession   = errors.New("failed to start session")
	ErrEndSession     = errors.New("failed to end session")
	ErrFetchSession   = errors.New("failed to fetch session")
	ErrRefreshSession = errors.New("failed to refresh session")
	ErrInvalidSession = errors.New("session is invalid or expired")

	// Password-related errors
	ErrHashPassword   = errors.New("failed to hash password")
	ErrVerifyPassword = errors.New("failed to verify password")
	ErrInvalidPass    = errors.New("invalid password")
)

// TokenType defines types of tokens
type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)

// Claims holds JWT token claims
type Claims struct {
	Subject   interface{} `json:"sub"`
	ExpiresAt time.Time   `json:"exp"`
}

// Session holds session data
type Session struct {
	SessionID string      `json:"session_id"`
	Subject   interface{} `json:"subject"`
	ExpiresAt time.Time   `json:"expires_at"`
}

// TokenHandler handles token operations
type TokenHandler interface {
	Generate(ctx context.Context, subject interface{}, tokenType TokenType) (string, error) // Generates token
	Validate(ctx context.Context, token string) (*Claims, error)                            // Validates token
	Invalidate(ctx context.Context, token string) error                                     // Invalidates token
}

// SessionManager manages session operations
type SessionManager interface {
	Start(ctx context.Context, subject interface{}) (Session, error) // Starts session
	End(ctx context.Context, sessionID string) error                 // Ends session
	Get(ctx context.Context, sessionID string) (*Session, error)     // Retrieves session
	Refresh(ctx context.Context, sessionID string) (string, error)   // Refresh session

}

// SecureHasher manages secure hashing operations
type SecureHasher interface {
	Hash(data string) (string, error)  // Hashes data
	Compare(hashed, data string) error // Compares hash and data
}
