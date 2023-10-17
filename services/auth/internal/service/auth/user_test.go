package auth

import (
	"context"
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
	"github.com/ramyadmz/goauth/internal/data"
	"github.com/ramyadmz/goauth/internal/data/mock"
	"github.com/ramyadmz/goauth/internal/service/credentials"
	"github.com/ramyadmz/goauth/pkg/pb"
	mocks "github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRegisterUser_HappyPath(t *testing.T) {
	password := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), 10)

	user := &data.User{
		ID:             100,
		Username:       "user100",
		HashedPassword: hashedPassword,
		Email:          "user102@test.com",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	mockDAL := &mock.DataProvider{}
	mockDAL.On("CreateUser", mocks.Anything, mocks.Anything).Return(user, nil)

	authService := NewUserAuthService(mockDAL, &mock.TokenHandler{})

	_, err := authService.RegisterUser(context.Background(), &pb.RegisterUserRequest{
		Username: user.Username,
		Password: password,
		Email:    user.Email,
	})

	assert.Equal(t, err, nil)
}

func TestRegisterUser_InternalError(t *testing.T) {
	mockDAL := &mock.DataProvider{}
	mockDAL.On("CreateUser", mocks.Anything, mocks.Anything).Return(&data.User{}, errors.New("Error creating user in database"))

	authService := NewUserAuthService(mockDAL, &mock.TokenHandler{})

	_, err := authService.RegisterUser(context.Background(), &pb.RegisterUserRequest{
		Username: mocks.Anything,
		Password: mocks.Anything,
		Email:    mocks.Anything,
	})

	assert.Equal(t, status.Code(err), codes.Internal)
}

func TestLoginUser_HappyPath(t *testing.T) {
	sessionID := "sessionID"
	password := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), 10)

	user := &data.User{
		ID:             100,
		Username:       "user100",
		HashedPassword: hashedPassword,
		Email:          "user102@test.com",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	mockDAL := &mock.DataProvider{}
	mockDAL.On("GetUserByUsername", mocks.Anything, mocks.Anything).Return(user, nil)

	mockSessionHandler := &mock.TokenHandler{}
	mockSessionHandler.On("Generate", mocks.Anything, mocks.Anything).Return(sessionID, nil)

	authService := NewUserAuthService(mockDAL, mockSessionHandler)

	rsp, err := authService.LoginUser(context.Background(), &pb.UserLoginRequest{
		Username: user.Username,
		Password: password,
	})

	assert.Equal(t, err, nil)
	assert.Equal(t, rsp.SessionId, sessionID)
}

func TestLoginUser_Unauthenticated(t *testing.T) {
	fakePassword := "fakePassword"
	password := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), 10)

	user := &data.User{
		ID:             100,
		Username:       "user100",
		HashedPassword: hashedPassword,
		Email:          "user102@test.com",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	mockDAL := &mock.DataProvider{}
	mockDAL.On("GetUserByUsername", mocks.Anything, mocks.Anything).Return(user, nil)

	authService := NewUserAuthService(mockDAL, &mock.TokenHandler{})

	_, err := authService.LoginUser(context.Background(), &pb.UserLoginRequest{
		Username: user.Username,
		Password: fakePassword,
	})

	assert.Equal(t, status.Code(err), codes.Unauthenticated)
}

func TestLogoutUser_HappyPath(t *testing.T) {
	mockSessionHandler := &mock.TokenHandler{}
	mockSessionHandler.On("Invalidate", mocks.Anything, mocks.Anything).Return(nil)

	authService := NewUserAuthService(&mock.DataProvider{}, mockSessionHandler)

	_, err := authService.LogoutUser(context.Background(), &pb.UserLogoutRequest{
		SessionId: mocks.Anything,
	})

	assert.Equal(t, err, nil)
}

func TestLogoutUser_Unauthenticated(t *testing.T) {
	mockSessionHandler := &mock.TokenHandler{}
	mockSessionHandler.On("Invalidate", mocks.Anything, mocks.Anything).Return(credentials.ErrInvalidToken)

	authService := NewUserAuthService(&mock.DataProvider{}, mockSessionHandler)

	_, err := authService.LogoutUser(context.Background(), &pb.UserLogoutRequest{
		SessionId: mocks.Anything,
	})

	assert.Equal(t, status.Code(err), codes.Unauthenticated)
}

func TestConsentUser_HappyPath(t *testing.T) {
	sessionID := "sessionID"
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

	mockDAL := &mock.DataProvider{}
	mockDAL.On("GetClientByID", mocks.Anything, mocks.Anything).Return(client, nil)
	mockDAL.On("CreateAuthorization", mocks.Anything, mocks.Anything, mocks.Anything).Return(&data.Authorization{}, nil)

	mockTokenHandler := &mock.TokenHandler{}
	mockTokenHandler.On("Validate", mocks.Anything, mocks.Anything).Return(&credentials.Claims{}, nil)

	authService := NewUserAuthService(mockDAL, mockTokenHandler)
	_, err := authService.ConsentUser(context.Background(), &pb.UserConsentRequest{
		ClientId:  client.ID,
		SessionId: sessionID,
	})

	assert.Equal(t, err, nil)
}

func TestConsentUser_Unauthenticated(t *testing.T) {

	mockTokenHandler := &mock.TokenHandler{}
	mockTokenHandler.On("Validate", mocks.Anything, mocks.Anything).Return(&credentials.Claims{}, credentials.ErrInvalidToken)

	authService := NewUserAuthService(&mock.DataProvider{}, mockTokenHandler)
	_, err := authService.ConsentUser(context.Background(), &pb.UserConsentRequest{
		ClientId:  rand.Int63(),
		SessionId: mocks.Anything,
	})

	assert.Equal(t, status.Code(err), codes.Unauthenticated)
}
