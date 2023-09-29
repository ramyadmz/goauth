package data

import "time"

type User struct {
	ID             int
	Username       string
	HashedPassword []byte
	Email          string
}

type Session struct {
	ID       string
	UserID   int
	ExpireAt time.Time
}

type Application struct {
	ID     string
	Secret string
}

type UserApplication struct {
	ID            string
	UserID        string
	ApplicationID string
	AuthCode      string
}
