package session

import (
	"context"
	"time"

	"github.com/ramyadmz/goauth/internal/data"
	"github.com/ramyadmz/goauth/internal/service/credentials"
)

// Compile time check for TokenHandler interface satisfaction.
var _ credentials.TokenHandler = new(SessionHandler)

type SessionHandler struct {
	dal data.DataProvider
}

func NewSessionHandler(dal data.DataProvider) *SessionHandler {
	return &SessionHandler{dal: dal}
}

func (s *SessionHandler) Generate(ctx context.Context, claims credentials.Claims) (string, error) {
	session, err := s.dal.CreateSession(ctx, data.CreateSessionParams{
		UserID:    claims.Subject,
		ExpiresAt: claims.ExpiresAt,
	})

	if err != nil {
		return "", credentials.ErrGeneratingToken
	}

	return session.ID, nil
}

func (s *SessionHandler) Validate(ctx context.Context, key string) (*credentials.Claims, error) {
	session, err := s.dal.GetSessionByID(ctx, key)
	if err != nil {
		if err == data.ErrSessionNotFound {
			return nil, credentials.ErrInvalidToken
		}
		return nil, err
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, credentials.ErrInvalidToken
	}

	return &credentials.Claims{
		Subject:   session.UserID,
		ExpiresAt: session.ExpiresAt,
	}, nil
}

func (s *SessionHandler) Invalidate(ctx context.Context, key string) error {
	// Here you would typically delete the session by its key (ID)
	err := s.dal.DeleteSessionByID(ctx, key)
	if err != nil {
		return credentials.ErrInvalidToken // Or some other custom error
	}
	return nil
}

func (s *SessionHandler) Refresh(ctx context.Context, key string) (string, error) {
	// Fetch old session
	session, err := s.dal.GetSessionByID(ctx, key)
	if err != nil {
		return "", credentials.ErrInvalidToken
	}

	// Update the session in your data store
	_, err = s.dal.UpdateSession(ctx, data.UpdateSessionParams{
		SessionID: session.ID,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	if err != nil {
		return "", credentials.ErrGeneratingToken
	}

	return session.ID, nil
}
