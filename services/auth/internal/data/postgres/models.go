package postgres

import (
	"time"

	"github.com/ramyadmz/goauth/internal/data"
)

type User struct {
	tableName      struct{}  `pg:"Users"`
	ID             int64     `pg:"id,serial,pk"`
	Username       string    `pg:"username,unique,notnull"`
	HashedPassword []byte    `pg:"hashed_password,notnull"`
	Email          string    `pg:"email,unique,notnull"`
	CreatedAt      time.Time `pg:"created_at,default:now()"`
	UpdatedAt      time.Time `pg:"updated_at"`
}

type Session struct {
	tableName struct{}  `pg:"Sessions"`
	ID        string    `pg:"id,pk"`
	UserID    int64     `pg:"user_id,notnull"`
	CreatedAt time.Time `pg:"created_at,default:now()"`
	ExpiresAt time.Time `pg:"expires_at"`
}

type Client struct {
	tableName    struct{}  `pg:"Clients"`
	ID           int64     `pg:"id,serial,pk"`
	HashedSecret []byte    `pg:"hashed_secret,notnull"`
	Name         string    `pg:"name,unique,notnull"`
	Website      string    `pg:"website,unique,notnull"`
	Scope        string    `pg:"scope"`
	CreatedAt    time.Time `pg:"created_at,default:now"`
	UpdatedAt    time.Time `pg:"updated_at"`
}

type Authorization struct {
	tableName struct{}  `pg:"Authorizations"`
	AuthCode  string    `pg:"auth_code,pk"`
	UserID    int64     `pg:"user_id,notnull"`
	ClientID  int64     `pg:"client_id,notnull"`
	Scope     string    `pg:"scope"`
	CreatedAt time.Time `pg:"created_at,default:now"`
	ExpiresAt time.Time `pg:"expires_at,notnull"`
	IsRevoked bool      `pg:"is_revoked,notnull"`
}

func (u *User) ToData() *data.User {
	return &data.User{
		ID:             u.ID,
		Username:       u.Username,
		HashedPassword: u.HashedPassword,
		Email:          u.Email,
		CreatedAt:      u.CreatedAt,
		UpdatedAt:      u.UpdatedAt,
	}
}

func (s *Session) ToData() *data.Session {
	return &data.Session{
		ID:        s.ID,
		UserID:    s.UserID,
		CreatedAt: s.CreatedAt,
		ExpiresAt: s.ExpiresAt,
	}
}

func (c *Client) ToData() *data.Client {
	return &data.Client{
		ID:           c.ID,
		HashedSecret: c.HashedSecret,
		Name:         c.Name,
		Website:      c.Website,
		Scope:        c.Scope,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
	}
}

func (a *Authorization) ToData() *data.Authorization {
	return &data.Authorization{
		AuthCode:  a.AuthCode,
		UserID:    a.UserID,
		ClientID:  a.ClientID,
		Scope:     a.Scope,
		CreatedAt: a.CreatedAt,
		ExpiresAt: a.ExpiresAt,
		IsRevoked: a.IsRevoked,
	}
}
