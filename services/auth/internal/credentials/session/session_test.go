package session

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ramyadmz/goauth/internal/data"
	"github.com/ramyadmz/goauth/internal/data/mock"
	"github.com/stretchr/testify/assert"
)

func TestStartSession_Success(t *testing.T) {
	mockDal := new(mock.DataProvider)
	sessionManager := NewSessionManager(mockDal)
	userID := rand.Int63()
	expiresAt := time.Now().Add(1 * time.Hour)
	sessionID := uuid.NewString()

	mockDal.On("CreateSession", context.Background(), data.CreateSessionParams{
		UserID:    userID,
		ExpiresAt: expiresAt,
	}).Return(&data.Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}, nil)

	res, err := sessionManager.Start(context.Background(), userID)
	assert.NoError(t, err)
	assert.Equal(t, sessionID, res.SessionID)
	assert.Equal(t, userID, res.Subject)
	assert.Equal(t, expiresAt.Truncate(time.Second), res.ExpiresAt.Truncate(time.Second))
}

func TestGetSession_Success(t *testing.T) {
	mockDal := new(mock.DataProvider)
	sessMgr := NewSessionManager(mockDal)
	userID := rand.Int63()
	sessionID := uuid.NewString()

	mockDal.On("GetSessionByID", context.Background(), userID).Return(data.Session{ID: sessionID, UserID: userID, ExpiresAt: time.Now().Add(1 * time.Hour)}, nil)

	session, err := sessMgr.Get(context.Background(), sessionID)
	assert.NoError(t, err)
	assert.Equal(t, sessionID, session.SessionID)
	assert.Equal(t, userID, session.Subject.(int64))
}

func TestEndSession_Success(t *testing.T) {
	mockDal := new(mock.DataProvider)
	sessMgr := NewSessionManager(mockDal)

	mockDal.On("DeleteSessionByID", context.Background(), "123").Return(nil)

	err := sessMgr.End(context.Background(), "123")
	assert.NoError(t, err)
}

func TestRefreshSession_Success(t *testing.T) {
	mockDal := new(mock.DataProvider)
	sessMgr := NewSessionManager(mockDal)

	mockDal.On("GetSessionByID", context.Background(), "123").Return(data.Session{ID: "123", UserID: int64(1), ExpiresAt: time.Now().Add(1 * time.Hour)}, nil)
	mockDal.On("UpdateSession", context.Background(), data.UpdateSessionParams{
		SessionID: "123",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}).Return(&data.Session{ID: "123", UserID: int64(1), ExpiresAt: time.Now().Add(1 * time.Hour)}, nil)

	newSessionID, err := sessMgr.Refresh(context.Background(), "123")
	assert.NoError(t, err)
	assert.Equal(t, "123", newSessionID)
}
