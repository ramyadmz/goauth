package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
	"github.com/google/uuid"
	tokenMock "github.com/ramyadmz/goauth/internal/credentials/mock"
	"github.com/ramyadmz/goauth/internal/data"
	dalMock "github.com/ramyadmz/goauth/internal/data/mock"

	"github.com/ramyadmz/goauth/internal/credentials"
	"github.com/ramyadmz/goauth/pkg/pb"
	mock "github.com/stretchr/testify/mock"

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

	mockDAL := &dalMock.DataProvider{}
	mockDAL.On("CreateClient", mock.Anything, mock.Anything).Return(client, nil)

	authService := NewClientAuthService(mockDAL, &tokenMock.TokenHandler{})

	rsp, err := authService.RegisterClient(context.Background(), &pb.RegisterClientRequest{Name: client.Name, Website: client.Website, Scope: client.Scope})

	assert.Equal(t, err, nil)
	assert.Equal(t, rsp.ClientId, client.ID)
	assert.NotEqual(t, len(rsp.ClientSecret), 0)
}

func TestRegisterClient_InternalError(t *testing.T) {
	client := &data.Client{}

	mockDAL := &dalMock.DataProvider{}
	mockDAL.On("CreateClient", mock.Anything, mock.Anything).Return(client, errors.New("failed to create client"))

	authService := NewClientAuthService(mockDAL, &tokenMock.TokenHandler{})

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

	mockDAL := &dalMock.DataProvider{}
	mockDAL.On("GetClientByID", mock.Anything, mock.Anything).Return(client, nil)
	mockDAL.On("GetUserByUsername", mock.Anything, mock.Anything).Return(user, nil)
	mockDAL.On("GetAuthorizationCodeByUserIDAndClientID", mock.Anything, mock.Anything, mock.Anything).Return(authorization, nil)

	authService := NewClientAuthService(mockDAL, &tokenMock.TokenHandler{})
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

	mockDAL := &dalMock.DataProvider{}
	mockDAL.On("GetClientByID", mock.Anything, mock.Anything).Return(client, nil)

	authService := NewClientAuthService(mockDAL, &tokenMock.TokenHandler{})
	_, err := authService.GetAuthorizationCode(context.Background(), &pb.GetAuthorizationCodeRequest{
		ClientId:     client.ID,
		Username:     mock.Anything,
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

	mockDAL := &dalMock.DataProvider{}
	mockDAL.On("GetClientByID", mock.Anything, mock.Anything).Return(client, nil)
	mockDAL.On("GetAuthorizationCodeByAuthCode", mock.Anything, mock.Anything, mock.Anything).Return(authorization, nil)

	mockTokenHandler := &tokenMock.TokenHandler{}
	mockTokenHandler.On("Generate", mock.Anything, mock.Anything).Times(1).Return(accessToken, nil)
	mockTokenHandler.On("Generate", mock.Anything, mock.Anything).Times(2).Return(refreshToken, nil)

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

	mockDAL := &dalMock.DataProvider{}
	mockDAL.On("GetClientByID", mock.Anything, mock.Anything).Return(client, nil)
	mockDAL.On("GetAuthorizationCodeByAuthCode", mock.Anything, mock.Anything, mock.Anything).Return(authorization, nil)

	mockTokenHandler := &tokenMock.TokenHandler{}
	mockTokenHandler.On("Generate", mock.Anything, mock.Anything).Times(1).Return(accessToken, nil)
	mockTokenHandler.On("Generate", mock.Anything, mock.Anything).Times(2).Return(refreshToken, nil)

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

	mockTokenHandler := &tokenMock.TokenHandler{}
	mockTokenHandler.On("Validate", mock.Anything, mock.Anything).Return(&credentials.Claims{}, nil)
	mockTokenHandler.On("Generate", mock.Anything, mock.Anything).Return(accessToken, nil)

	authService := NewClientAuthService(&dalMock.DataProvider{}, mockTokenHandler)
	rsp, err := authService.RefreshToken(context.Background(), &pb.RefreshTokenRequest{
		RefreshToken: mock.Anything,
	})

	assert.Equal(t, err, nil)
	assert.Equal(t, rsp.AccessToken, accessToken)
}

func TestRefreshToken_Unauthenticated(t *testing.T) {

	mockTokenHandler := &tokenMock.TokenHandler{}
	mockTokenHandler.On("Validate", mock.Anything, mock.Anything).Return(&credentials.Claims{}, credentials.ErrInvalidToken)

	authService := NewClientAuthService(&dalMock.DataProvider{}, mockTokenHandler)
	_, err := authService.RefreshToken(context.Background(), &pb.RefreshTokenRequest{
		RefreshToken: mock.Anything,
	})

	assert.Equal(t, status.Code(err), codes.Unauthenticated)
}
