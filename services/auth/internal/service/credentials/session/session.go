package session

import (
	"context"
	"time"

	"github.com/ramyadmz/goauth/internal/data"
	"github.com/ramyadmz/goauth/internal/service/credentials"
)

type SessionHandler struct {
	DAL data.AuthProvider
}

func (s *SessionHandler) Generate(ctx context.Context, claims credentials.Claims) (string, error) {
	session, err := s.DAL.CreateSession(ctx, data.CreateSessionParams{
		UserID:    claims.Subject,
		ExpiresAt: claims.ExpiresAt,
	})

	if err != nil {
		return "", credentials.ErrGeneratingToken
	}

	return session.ID, nil
}

func (s *SessionHandler) Validate(ctx context.Context, key string) (interface{}, error) {
	session, err := s.DAL.GetSessionByID(ctx, key)
	if err != nil {
		if err == data.ErrSessionNotFound {
			return nil, credentials.ErrInvalidToken
		}
		return nil, err
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, credentials.ErrInvalidToken
	}

	return session.UserID, nil
}

func (s *SessionHandler) Invalidate(ctx context.Context, key string) (interface{}, error) {
	// Here you would typically delete the session by its key (ID)
	err := s.DAL.DeleteSessionByID(ctx, key)
	if err != nil {
		return nil, credentials.ErrInvalidToken // Or some other custom error
	}
	return nil, nil
}

func (s *SessionHandler) Refresh(ctx context.Context, key string) (string, error) {
	// Fetch old session
	session, err := s.DAL.GetSessionByID(ctx, key)
	if err != nil {
		return "", credentials.ErrInvalidToken
	}

	// Update the session in your data store
	_, err = s.DAL.UpdateSession(ctx, data.UpdateSessionParams{
		SessionID: session.ID,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	if err != nil {
		return "", credentials.ErrGeneratingToken
	}

	return session.ID, nil
}
