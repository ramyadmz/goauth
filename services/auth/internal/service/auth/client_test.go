package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
	"github.com/google/uuid"
	"github.com/ramyadmz/goauth/internal/data"
	mock "github.com/ramyadmz/goauth/internal/data/mock"

	"github.com/ramyadmz/goauth/internal/service/credentials"
	"github.com/ramyadmz/goauth/pkg/pb"
	mocks "github.com/stretchr/testify/mock"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRegisterClient_HappyPath(t *testing.T) {
	client := &data.Client{
		ID:           101,
		HashedSecret: []byte("veryHashedSecret"),
		Name:         "name",
		Website:      "test.com",
		Scope:        "read",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	mockDAL := &mock.DataProvider{}
	mockDAL.On("CreateClient", mocks.Anything, mocks.Anything).Return(client, nil)

	authService := NewClientAuthService(mockDAL, &mock.TokenHandler{})

	rsp, err := authService.RegisterClient(context.Background(), &pb.RegisterClientRequest{Name: client.Name, Website: client.Website, Scope: client.Scope})

	assert.Equal(t, err, nil)
	assert.Equal(t, rsp.ClientId, client.ID)
	assert.NotEqual(t, len(rsp.ClientSecret), 0)
}

func TestRegisterClient_InternalError(t *testing.T) {
	client := &data.Client{}

	mockDAL := &mock.DataProvider{}
	mockDAL.On("CreateClient", mocks.Anything, mocks.Anything).Return(client, errors.New("failed to create client"))

	authService := NewClientAuthService(mockDAL, &mock.TokenHandler{})

	rsp, err := authService.RegisterClient(context.Background(), &pb.RegisterClientRequest{Name: client.Name, Website: client.Website, Scope: client.Scope})
	assert.NotEqual(t, err, nil)
	assert.Equal(t, rsp, nil)
}

func TestGetAuthorizationCode_HappyPath(t *testing.T) {
	clientSecret := "123abc"
	hashedSec, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), 10)
	client := &data.Client{
		ID:           101,
		HashedSecret: hashedSec,
		Name:         "name",
		Website:      "test.com",
		Scope:        "read",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	user := &data.User{
		ID:             102,
		Username:       "user102",
		HashedPassword: []byte("hashedpassword"),
		Email:          "user102@test.com",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	authorization := &data.Authorization{
		UserID:    user.ID,
		ClientID:  client.ID,
		AuthCode:  uuid.NewString(),
		Scope:     "scope",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(15 * time.Minute),
		IsRevoked: false,
	}

	mockDAL := &mock.DataProvider{}
	mockDAL.On("GetClientByID", mocks.Anything, mocks.Anything).Return(client, nil)
	mockDAL.On("GetUserByUsername", mocks.Anything, mocks.Anything).Return(user, nil)
	mockDAL.On("GetAuthorizationCodeByUserIDAndClientID", mocks.Anything, mocks.Anything, mocks.Anything).Return(authorization, nil)

	authService := NewClientAuthService(mockDAL, &mock.TokenHandler{})
	rsp, err := authService.GetAuthorizationCode(context.Background(), &pb.GetAuthorizationCodeRequest{
		ClientId:     client.ID,
		Username:     user.Username,
		ClientSecret: clientSecret,
	})
	assert.Equal(t, err, nil)
	assert.Equal(t, rsp.AuthorizationCode, authorization.AuthCode)
}

func TestGetAuthorizationCode_Unauthenticated(t *testing.T) {
	clientSecret := "123abc"
	hashedSec, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), 10)
	invalidclientSecret := "inavlidSec"
	client := &data.Client{
		ID:           101,
		HashedSecret: hashedSec,
		Name:         "name",
		Website:      "test.com",
		Scope:        "read",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	mockDAL := &mock.DataProvider{}
	mockDAL.On("GetClientByID", mocks.Anything, mocks.Anything).Return(client, nil)

	authService := NewClientAuthService(mockDAL, &mock.TokenHandler{})
	_, err := authService.GetAuthorizationCode(context.Background(), &pb.GetAuthorizationCodeRequest{
		ClientId:     client.ID,
		Username:     mocks.Anything,
		ClientSecret: invalidclientSecret,
	})
	assert.Equal(t, status.Code(err), codes.Unauthenticated)
}

func TestExchangeToken_HappyPath(t *testing.T) {
	clientSecret := "123abc"
	accessToken := "accessToken"
	refreshToken := "refreshToken"
	hashedSec, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), 10)
	client := &data.Client{
		ID:           101,
		HashedSecret: hashedSec,
		Name:         "name",
		Website:      "test.com",
		Scope:        "read",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	authorization := &data.Authorization{
		UserID:    102,
		ClientID:  client.ID,
		AuthCode:  uuid.NewString(),
		Scope:     "scope",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(15 * time.Minute),
		IsRevoked: false,
	}

	mockDAL := &mock.DataProvider{}
	mockDAL.On("GetClientByID", mocks.Anything, mocks.Anything).Return(client, nil)
	mockDAL.On("GetAuthorizationCodeByAuthCode", mocks.Anything, mocks.Anything, mocks.Anything).Return(authorization, nil)

	mockTokenHandler := &mock.TokenHandler{}
	mockTokenHandler.On("Generate", mocks.Anything, mocks.Anything).Times(1).Return(accessToken, nil)
	mockTokenHandler.On("Generate", mocks.Anything, mocks.Anything).Times(2).Return(refreshToken, nil)

	authService := NewClientAuthService(mockDAL, mockTokenHandler)
	rsp, err := authService.ExchangeToken(context.Background(), &pb.ExchangeTokenRequest{
		ClientId:          client.ID,
		ClientSecret:      clientSecret,
		AuthorizationCode: authorization.AuthCode,
	})

	assert.Equal(t, err, nil)
	assert.Equal(t, rsp.AccessToken, accessToken)
	assert.Equal(t, rsp.RefreshToken, refreshToken)
}

func TestExchangeToken_Unauthenticated(t *testing.T) {
	invalidClientID := int64(100)
	clientSecret := "123abc"
	accessToken := "accessToken"
	refreshToken := "refreshToken"
	hashedSec, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), 10)
	client := &data.Client{
		ID:           101,
		HashedSecret: hashedSec,
		Name:         "name",
		Website:      "test.com",
		Scope:        "read",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	authorization := &data.Authorization{
		UserID:    102,
		ClientID:  invalidClientID,
		AuthCode:  uuid.NewString(),
		Scope:     "scope",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(15 * time.Minute),
		IsRevoked: false,
	}

	mockDAL := &mock.DataProvider{}
	mockDAL.On("GetClientByID", mocks.Anything, mocks.Anything).Return(client, nil)
	mockDAL.On("GetAuthorizationCodeByAuthCode", mocks.Anything, mocks.Anything, mocks.Anything).Return(authorization, nil)

	mockTokenHandler := &mock.TokenHandler{}
	mockTokenHandler.On("Generate", mocks.Anything, mocks.Anything).Times(1).Return(accessToken, nil)
	mockTokenHandler.On("Generate", mocks.Anything, mocks.Anything).Times(2).Return(refreshToken, nil)

	authService := NewClientAuthService(mockDAL, mockTokenHandler)
	_, err := authService.ExchangeToken(context.Background(), &pb.ExchangeTokenRequest{
		ClientId:          client.ID,
		ClientSecret:      clientSecret,
		AuthorizationCode: authorization.AuthCode,
	})

	assert.Equal(t, status.Code(err), codes.Unauthenticated)

}

func TestRefreshToken_HappyPath(t *testing.T) {
	accessToken := "accessToken"

	mockTokenHandler := &mock.TokenHandler{}
	mockTokenHandler.On("Validate", mocks.Anything, mocks.Anything).Return(&credentials.Claims{}, nil)
	mockTokenHandler.On("Generate", mocks.Anything, mocks.Anything).Return(accessToken, nil)

	authService := NewClientAuthService(&mock.DataProvider{}, mockTokenHandler)
	rsp, err := authService.RefreshToken(context.Background(), &pb.RefreshTokenRequest{
		RefreshToken: mocks.Anything,
	})

	assert.Equal(t, err, nil)
	assert.Equal(t, rsp.AccessToken, accessToken)
}

func TestRefreshToken_Unauthenticated(t *testing.T) {

	mockTokenHandler := &mock.TokenHandler{}
	mockTokenHandler.On("Validate", mocks.Anything, mocks.Anything).Return(&credentials.Claims{}, credentials.ErrInvalidToken)

	authService := NewClientAuthService(&mock.DataProvider{}, mockTokenHandler)
	_, err := authService.RefreshToken(context.Background(), &pb.RefreshTokenRequest{
		RefreshToken: mocks.Anything,
	})

	assert.Equal(t, status.Code(err), codes.Unauthenticated)
}
