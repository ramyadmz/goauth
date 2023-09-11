package postgres

import (
	"context"

	"github.com/go-pg/pg/v11"
	"github.com/ramyadmz/goauth/internal/data"
)

type PostgresProvider struct {
	db *pg.DB
}

// compile time check for interface satisfaction.
var _ data.AuthProvider = new(PostgresProvider)

func (pg *PostgresProvider) CreateUser(ctx context.Context, params data.CreateUseParams) (*data.User, error) {
	user := &User{
		UserName: params.Username,
		Password: params.Password,
		Email:    params.Email,
	}

	tx, err := pg.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	_, err = tx.Model(user).Insert(ctx)
	if err != nil {
		tx.Rollback(ctx)
		return nil, err
	}
	return user.ToData(), nil

}
