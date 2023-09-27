package postgres

import (
	"context"
	"fmt"

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
// It takes user creation parameters, begins a new transaction,
// inserts the new user, and commits the transaction.
func (pp *PostgresProvider) CreateUser(ctx context.Context, params data.CreateUseParams) (*data.User, error) {
	user := &User{
		UserName: params.Username,
		Password: params.Password,
		Email:    params.Email,
	}

	// Begin a new transaction
	tx, err := pp.db.Begin(ctx)
	if err != nil {
		return nil, err
	}

	// Insert the new user
	_, err = tx.Model(user).Insert(ctx)
	if err != nil {
		tx.Rollback(ctx)
		return nil, err
	}

	// Commit the transaction
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}

	return user.ToData(), nil
}

// GetUserByID retrieves a user by their ID from the database.
// It begins a new transaction, performs the selection, and commits the transaction.
func (pp *PostgresProvider) GetUserByID(ctx context.Context, userID string) (*data.User, error) {
	user := &User{
		ID: userID,
	}

	// Begin a new transaction
	tx, err := pp.db.Begin(ctx)
	if err != nil {
		return nil, err
	}

	// Select the user by ID
	err = tx.Model(user).Select(ctx)
	if err != nil {
		tx.Rollback(ctx)
		if err == pg.ErrNoRows {
			return nil, fmt.Errorf("user not found: %w", err)
		}
		return nil, err
	}

	// Commit the transaction
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}

	return user.ToData(), nil
}

func (pp *PostgresProvider) GetUserByUsername(ctx context.Context, username string) (*data.User, error) {
	user := &data.User{Username: username}
	tx, err := pp.db.Begin(ctx)
	if err != nil {
		return nil, err
	}

	err = tx.Model(user).Select(ctx)
	if err != nil {
		tx.Rollback(ctx)
		if err == pg.ErrNoRows {
			return nil, fmt.Errorf("user not found: %w", err)
		}
		return nil, err
	}

	// Commit the transaction
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return user, nil
}
