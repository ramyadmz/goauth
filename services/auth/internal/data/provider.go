package data

import (
	"context"
	"errors"
	"time"
)

var (
	ErrUserNotFound          = errors.New("user not found")
	ErrClientNotFound        = errors.New("client not found")
	ErrSessionNotFound       = errors.New("session not found")
	ErrAuthorizationNotFound = errors.New("auth code not found")
	ErrUserCreation          = errors.New("failed to create user")
	ErrSessionCreation       = errors.New("failed to create session")
	ErrInvalidCredential     = errors.New("invalid credentials")
	// Add more as needed
)

type CreateClientParams struct {
	Name         string
	Website      string
	Scope        string
	HashedSecret string
}

type CreateAuthorizationParams struct {
	UserID   int64
	ClientID int64
	Scope    string
}

type CreateUserParams struct {
	Username       string
	HashedPassword []byte
	Email          string
}

type CreateSessionParams struct {
	UserID    int64
	ExpiresAt time.Time
}

type UpdateSessionParams struct {
	SessionID string
	ExpiresAt time.Time
}

type AuthProvider interface {
	CreateUser(ctx context.Context, params CreateUserParams) (*User, error)
	GetUserByID(ctx context.Context, userID int64) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)

	CreateSession(ctx context.Context, params CreateSessionParams) (*Session, error)
	DeleteSessionByID(ctx context.Context, sessionID string) error
	UpdateSession(ctx context.Context, params UpdateSessionParams) (*Session, error)
	GetSessionByID(ctx context.Context, sessionID string) (*Session, error)

	CreateClient(ctx context.Context, params CreateClientParams) (*Client, error)
	GetClientByID(ctx context.Context, clientID int64) (*Client, error)

	CreateAuthorization(ctx context.Context, params CreateAuthorizationParams) (*Authorization, error)
	GetAuthorizationCodeByAuthCode(ctx context.Context, authCode string) (*Authorization, error)
	GetAuthorizationCodeByUserIDAndClientID(ctx context.Context, clientID, userID int64) (*Authorization, error)
	RevokeAuthorizationByUserID(ctx context.Context, userID int64) error
}
