package session

import "github.com/google/uuid"

type SessionHandler struct {
}

func (s *SessionHandler) Generate(data interface{}) (string, error) {
	userID := data.(string)
	_ = userID
	sessionID := uuid.New().String()
	// insert to DB for userID
	return sessionID, nil
}

func (s *SessionHandler) Validate(key string) (interface{}, error) {
	var userID string
	// check session id and retrive userId
	return userID, nil
}

func (s *SessionHandler) Invalidate(key string) (interface{}, error) {
	return nil, nil
}
func (s *SessionHandler) Refresh(key string) (string, error) {
	return "", nil
}
