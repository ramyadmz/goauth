package data

import "context"

type CreateUseParams struct {
	Username string
	Password string
	Email    string
}

type AuthProvider interface {
	CreateUser(ctx context.Context, params CreateUseParams) (*User, error)
	GetUserByID(ctx context.Context, UserID string) (*User, error)
}
