package mock

import (
	"context"

	"github.com/ramyadmz/goauth/internal/data"
	"github.com/stretchr/testify/mock"
)

type DataProvider struct {
	mock.Mock
}

// Compile-time check to ensure mock DataProvider satisfies the data.DataProvider interface.
var _ data.DataProvider = new(DataProvider)

func (m *DataProvider) CreateUser(ctx context.Context, params data.CreateUserParams) (*data.User, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*data.User), args.Error(1)
}
func (m *DataProvider) GetUserByID(ctx context.Context, userID int64) (*data.User, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(*data.User), args.Error(1)
}
func (m *DataProvider) GetUserByUsername(ctx context.Context, username string) (*data.User, error) {
	args := m.Called(ctx, username)
	return args.Get(0).(*data.User), args.Error(1)
}

func (m *DataProvider) CreateSession(ctx context.Context, params data.CreateSessionParams) (*data.Session, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*data.Session), args.Error(1)
}
func (m *DataProvider) DeleteSessionByID(ctx context.Context, sessionID string) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}
func (m *DataProvider) UpdateSession(ctx context.Context, params data.UpdateSessionParams) (*data.Session, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*data.Session), args.Error(1)
}
func (m *DataProvider) GetSessionByID(ctx context.Context, sessionID string) (*data.Session, error) {
	args := m.Called(ctx, sessionID)
	return args.Get(0).(*data.Session), args.Error(1)
}

func (m *DataProvider) CreateClient(ctx context.Context, params data.CreateClientParams) (*data.Client, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*data.Client), args.Error(1)
}

func (m *DataProvider) GetClientByID(ctx context.Context, clientID int64) (*data.Client, error) {
	args := m.Called(ctx, clientID)
	return args.Get(0).(*data.Client), args.Error(1)
}

func (m *DataProvider) CreateAuthorization(ctx context.Context, params data.CreateAuthorizationParams) (*data.Authorization, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*data.Authorization), args.Error(1)
}

func (m *DataProvider) GetAuthorizationCodeByAuthCode(ctx context.Context, authCode string) (*data.Authorization, error) {
	args := m.Called(ctx, authCode)
	return args.Get(0).(*data.Authorization), args.Error(1)
}

func (m *DataProvider) GetAuthorizationCodeByUserIDAndClientID(ctx context.Context, clientID, userID int64) (*data.Authorization, error) {
	args := m.Called(ctx, clientID, userID)
	return args.Get(0).(*data.Authorization), args.Error(1)
}

func (m *DataProvider) RevokeAuthorizationByUserID(ctx context.Context, userID int64) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}
