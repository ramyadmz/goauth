package auth

import (
	"context"

	"github.com/ramyadmz/goauth/internal/data"
	"github.com/ramyadmz/goauth/internal/service/credentials"
	"github.com/stretchr/testify/mock"
)

type MockDAL struct {
	mock.Mock
}

func (m *MockDAL) CreateUser(ctx context.Context, params data.CreateUserParams) (*data.User, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*data.User), args.Error(1)
}
func (m *MockDAL) GetUserByID(ctx context.Context, userID int64) (*data.User, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(*data.User), args.Error(1)
}
func (m *MockDAL) GetUserByUsername(ctx context.Context, username string) (*data.User, error) {
	args := m.Called(ctx, username)
	return args.Get(0).(*data.User), args.Error(1)
}

func (m *MockDAL) CreateSession(ctx context.Context, params data.CreateSessionParams) (*data.Session, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*data.Session), args.Error(1)
}
func (m *MockDAL) DeleteSessionByID(ctx context.Context, sessionID string) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}
func (m *MockDAL) UpdateSession(ctx context.Context, params data.UpdateSessionParams) (*data.Session, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*data.Session), args.Error(1)
}
func (m *MockDAL) GetSessionByID(ctx context.Context, sessionID string) (*data.Session, error) {
	args := m.Called(ctx, sessionID)
	return args.Get(0).(*data.Session), args.Error(1)
}

func (m *MockDAL) CreateClient(ctx context.Context, params data.CreateClientParams) (*data.Client, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*data.Client), args.Error(1)
}

func (m *MockDAL) GetClientByID(ctx context.Context, clientID int64) (*data.Client, error) {
	args := m.Called(ctx, clientID)
	return args.Get(0).(*data.Client), args.Error(1)
}

func (m *MockDAL) CreateAuthorization(ctx context.Context, params data.CreateAuthorizationParams) (*data.Authorization, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*data.Authorization), args.Error(1)
}

func (m *MockDAL) GetAuthorizationCodeByAuthCode(ctx context.Context, authCode string) (*data.Authorization, error) {
	args := m.Called(ctx, authCode)
	return args.Get(0).(*data.Authorization), args.Error(1)
}

func (m *MockDAL) GetAuthorizationCodeByUserIDAndClientID(ctx context.Context, clientID, userID int64) (*data.Authorization, error) {
	args := m.Called(ctx, clientID, userID)
	return args.Get(0).(*data.Authorization), args.Error(1)
}

func (m *MockDAL) RevokeAuthorizationByUserID(ctx context.Context, userID int64) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

type MockTokenHandler struct {
	mock.Mock
}

func (m *MockTokenHandler) Generate(ctx context.Context, claims credentials.Claims) (string, error) {
	args := m.Called(ctx, claims)
	return args.String(0), args.Error(1)
}

func (m *MockTokenHandler) Validate(ctx context.Context, token string) (*credentials.Claims, error) {
	args := m.Called(ctx, token)
	return args.Get(0).(*credentials.Claims), args.Error(1)
}

func (m *MockTokenHandler) Invalidate(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}
