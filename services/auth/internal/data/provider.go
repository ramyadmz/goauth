package data

import (
	"context"
	"errors"
	"time"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrSessionNotFound   = errors.New("session not found")
	ErrUserCreation      = errors.New("failed to create user")
	ErrSessionCreation   = errors.New("failed to create session")
	ErrInvalidCredential = errors.New("invalid credentials")
	// Add more as needed
)

type CreateUserParams struct {
	Username       string
	HashedPassword []byte
	Email          string
}

type UpdateSessionParams struct {
	SessionID string
	ExpiresAt time.Time
}

type AuthProvider interface {
	CreateUser(ctx context.Context, params CreateUserParams) (*User, error)
	GetUserByID(ctx context.Context, userID int) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)

	CreateSession(ctx context.Context, userID int) (*Session, error)
	DeleteSessionByID(ctx context.Context, sessionID string) error
	UpdateSession(ctx context.Context, params UpdateSessionParams) (*Session, error)
	GetSessionByID(ctx context.Context, sessionID string) (*Session, error)
}
