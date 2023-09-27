package data

import "context"

type CreateUseParams struct {
	Username string
	Password []byte
	Email    string
}

type AuthProvider interface {
	CreateUser(ctx context.Context, params CreateUseParams) (*User, error)
	GetUserByID(ctx context.Context, userID string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
}
