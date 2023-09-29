package postgres

import (
	"time"

	"github.com/ramyadmz/goauth/internal/data"
)

type User struct {
	tableName      struct{}  `pg:"Users"`
	ID             int       `pg:"id,serial,pk"`
	Username       string    `pg:"username,unique,notnull"`
	HashedPassword []byte    `pg:"password,notnull"` // Encrypted
	Email          string    `pg:"email,unique,notnull"`
	CreatedAt      time.Time `pg:"created_at,default:now()"`
	UpdatedAt      time.Time `pg:"updated_at"`
}

type Session struct {
	tableName struct{}  `pg:"Sessions"`
	ID        string    `pg:"id,type:uuid,default:uuid_generate_v4(),pk"`
	UserID    int       `pg:"user_id"`
	ExpiresAt time.Time `pg:"expires_at"`
}

func (u *User) ToData() *data.User {
	return &data.User{
		ID:             u.ID,
		Username:       u.Username,
		HashedPassword: u.HashedPassword,
		Email:          u.Email,
	}
}

func (s *Session) ToData() *data.Session {
	return &data.Session{
		ID:       s.ID,
		UserID:   s.UserID,
		ExpireAt: s.ExpiresAt,
	}
}
