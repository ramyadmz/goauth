package data

import "time"

type User struct {
	ID             int64
	Username       string
	HashedPassword []byte
	Email          string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type Session struct {
	ID        string
	UserID    int64
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Client struct {
	ID           int64
	HashedSecret []byte
	Name         string
	Website      string
	Scope        string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type Authorization struct {
	AuthCode  string
	UserID    int64
	ClientID  int64
	Scope     string
	CreatedAt time.Time
	ExpiresAt time.Time
	IsRevoked bool
}
