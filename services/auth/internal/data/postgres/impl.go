package postgres

import (
	"context"
	"time"

	"github.com/go-pg/pg/v11"
	"github.com/ramyadmz/goauth/internal/data"
)

// PostgresProvider implements the AuthProvider interface using PostgreSQL as a backend.
type PostgresProvider struct {
	db *pg.DB
}

// Compile-time check to ensure PostgresProvider satisfies the data.AuthProvider interface.
var _ data.AuthProvider = new(PostgresProvider)

// CreateUser creates a new user in the database.
func (p *PostgresProvider) CreateUser(ctx context.Context, params data.CreateUserParams) (*data.User, error) {
	user := &User{
		Username:       params.Username,
		HashedPassword: params.HashedPassword,
		Email:          params.Email,
	}

	_, err := p.db.Model(user).Insert(ctx)
	if err != nil {
		return nil, data.ErrUserCreation
	}

	return user.ToData(), nil
}

// GetUserByID retrieves a user by their ID from the database.
func (p *PostgresProvider) GetUserByID(ctx context.Context, userID int) (*data.User, error) {
	user := &User{ID: userID}

	err := p.db.Model(user).WherePK().Select(ctx)
	if err != nil {
		if err == pg.ErrNoRows {
			return nil, data.ErrUserNotFound
		}
		return nil, err
	}

	return user.ToData(), nil
}

func (p *PostgresProvider) GetUserByUsername(ctx context.Context, username string) (*data.User, error) {
	user := &User{Username: username}

	err := p.db.Model(user).Select(ctx)
	if err != nil {
		if err == pg.ErrNoRows {
			return nil, data.ErrUserNotFound
		}
		return nil, err
	}

	return user.ToData(), nil
}

// CreateSession creates a new session in the database.
func (p *PostgresProvider) CreateSession(ctx context.Context, userID int) (*data.Session, error) {
	session := &Session{
		UserID:    userID,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	_, err := p.db.Model(session).Insert(ctx)
	if err != nil {
		return nil, data.ErrSessionCreation
	}

	return session.ToData(), nil
}

// GetSessionByID retrieves a session by ID from the database.
func (p *PostgresProvider) GetSessionByID(ctx context.Context, sessionID string) (*data.Session, error) {
	session := &Session{
		ID: sessionID,
	}

	err := p.db.Model(session).WherePK().Select(ctx)
	if err != nil {
		if err == pg.ErrNoRows {
			return nil, data.ErrSessionNotFound
		}
		return nil, err
	}

	return session.ToData(), nil
}
