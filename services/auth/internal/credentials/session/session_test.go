package session

import (
	"context"
	"testing"
	"time"

	"github.com/ramyadmz/goauth/internal/data"
	"github.com/ramyadmz/goauth/internal/data/mock"
	"github.com/stretchr/testify/assert"
)

func TestStartSession_Success(t *testing.T) {
	mockDal := new(mock.DataProvider)
	sessMgr := NewSessionManager(mockDal)

	mockDal.On("CreateSession", context.Background(), data.CreateSessionParams{
		UserID:    int64(1),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}).Return(data.Session{ID: "123", UserID: int64(1), ExpiresAt: time.Now().Add(1 * time.Hour)}, nil)

	sess, err := sessMgr.Start(context.Background(), int64(1))
	assert.NoError(t, err)
	assert.Equal(t, "123", sess.SessionID)
}

func TestGetSession_Success(t *testing.T) {
	mockDal := new(mock.DataProvider)
	sessMgr := NewSessionManager(mockDal)

	mockDal.On("GetSessionByID", context.Background(), "123").Return(data.Session{ID: "123", UserID: int64(1), ExpiresAt: time.Now().Add(1 * time.Hour)}, nil)

	sess, err := sessMgr.Get(context.Background(), "123")
	assert.NoError(t, err)
	assert.Equal(t, "123", sess.SessionID)
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
	}).Return(data.Session{ID: "123", UserID: int64(1), ExpiresAt: time.Now().Add(1 * time.Hour)}, nil)

	newSessionID, err := sessMgr.Refresh(context.Background(), "123")
	assert.NoError(t, err)
	assert.Equal(t, "123", newSessionID)
}
