package postgres

import (
	"time"

	"github.com/ramyadmz/goauth/internal/data"
)

type User struct {
	tableName struct{}  `pg:"Users"`
	ID        string    `pg:"id,pk"`
	UserName  string    `pg:"username,unique,notnull"`
	Password  []byte    `pg:"password,notnull"` // Encrypted
	Email     string    `pg:"email,unique,notnull"`
	CreatedAt time.Time `pg:"created_at,default:now()"`
	UpdatedAt time.Time `pg:"updated_at"`
}

func (u *User) ToData() *data.User {
	return &data.User{
		ID:       u.ID,
		Username: u.UserName,
		Password: u.Password,
		Email:    u.Email,
	}
}
