package mock

import (
	"context"

	"github.com/ramyadmz/goauth/internal/credentials"
	"github.com/stretchr/testify/mock"
)

type TokenHandler struct {
	mock.Mock
}

// Compile-time check to ensure mock DataProvider satisfies the data.DataProvider interface.
var _ credentials.TokenHandler = new(TokenHandler)

func (t *TokenHandler) Generate(ctx context.Context, subject interface{}, tokenType credentials.TokenType) (string, error) {
	args := t.Called(ctx, subject, tokenType)
	return args.String(0), args.Error(1)
}

func (t *TokenHandler) Validate(ctx context.Context, token string) (*credentials.Claims, error) {
	args := t.Called(ctx, token)
	return args.Get(0).(*credentials.Claims), args.Error(1)
}

func (t *TokenHandler) Invalidate(ctx context.Context, token string) error {
	args := t.Called(ctx, token)
	return args.Error(0)
}

type SessionManager struct {
	mock.Mock
}

// Compile-time check to ensure mock DataProvider satisfies the data.DataProvider interface.
var _ credentials.SessionManager = new(SessionManager)

func (s *SessionManager) Start(ctx context.Context, subject interface{}) (credentials.Session, error) {
	args := s.Called(ctx, subject)
	return args.Get(0).(credentials.Session), args.Error(1)
}
func (s *SessionManager) End(ctx context.Context, sessionID string) error {
	args := s.Called(ctx, sessionID)
	return args.Error(0)
}

func (s *SessionManager) Get(ctx context.Context, sessionID string) (*credentials.Session, error) {
	args := s.Called(ctx, sessionID)
	return args.Get(0).(*credentials.Session), args.Error(1)
}

func (s *SessionManager) Refresh(ctx context.Context, sessionID string) (string, error) {
	args := s.Called(ctx, sessionID)
	return args.String(0), args.Error(1)
}
