// Package session provides functionalities for managing user sessions.
package session

import (
	"context"
	"time"

	"github.com/ramyadmz/goauth/internal/credentials"
	"github.com/ramyadmz/goauth/internal/data"
)

// Ensure SessionManager implements the SessionManager interface from the credentials package.
var _ credentials.SessionManager = new(SessionManager)

// SessionManager is responsible for managing user sessions.
type SessionManager struct {
	dal data.DataProvider // Data access layer
}

// NewSessionManager initializes a new SessionManager.
func NewSessionManager(dataProvider data.DataProvider) *SessionManager {
	return &SessionManager{
		dal: dataProvider,
	}
}

// Start creates a new session for a given subject (user).
func (s *SessionManager) Start(ctx context.Context, subject interface{}) (credentials.Session, error) {
	// Create a new session in the data store
	session, err := s.dal.CreateSession(ctx, data.CreateSessionParams{
		UserID:    subject.(int64),
		ExpiresAt: time.Now().Add(1 * time.Hour), // TODO: Get this value from config or env vars
	})

	// Handle errors during session creation
	if err != nil {
		return credentials.Session{}, credentials.ErrStartSession
	}

	// Return the newly created session
	return credentials.Session{
		SessionID: session.ID,
		Subject:   session.UserID,
		ExpiresAt: session.ExpiresAt,
	}, nil
}

// Get retrieves a session by its ID.
func (s *SessionManager) Get(ctx context.Context, sessionID string) (*credentials.Session, error) {
	// Fetch the session from the data store
	session, err := s.dal.GetSessionByID(ctx, sessionID)
	if err != nil {
		if err == data.ErrSessionNotFound {
			return nil, credentials.ErrInvalidSession
		}
		return nil, credentials.ErrFetchSession
	}

	// Check if the session has expired
	if time.Now().After(session.ExpiresAt) {
		return nil, credentials.ErrInvalidSession
	}

	// Return the fetched session
	return &credentials.Session{
		SessionID: session.ID,
		Subject:   session.UserID,
		ExpiresAt: session.ExpiresAt,
	}, nil
}

// End terminates a session by its ID.
func (s *SessionManager) End(ctx context.Context, sessionID string) error {
	// Delete the session from the data store
	err := s.dal.DeleteSessionByID(ctx, sessionID)
	if err != nil {
		return credentials.ErrEndSession
	}
	return nil
}

// Refresh extends the expiration time of a session.
func (s *SessionManager) Refresh(ctx context.Context, sessionID string) (string, error) {
	// Fetch the existing session
	session, err := s.dal.GetSessionByID(ctx, sessionID)
	if err != nil {
		return "", credentials.ErrInvalidSession
	}

	// Update the session's expiration time
	_, err = s.dal.UpdateSession(ctx, data.UpdateSessionParams{
		SessionID: session.ID,
		ExpiresAt: time.Now().Add(1 * time.Hour), // TODO: Get this value from config or env vars
	})

	// Handle errors during session update
	if err != nil {
		return "", credentials.ErrRefreshSession
	}

	// Return the updated session ID
	return session.ID, nil
}
