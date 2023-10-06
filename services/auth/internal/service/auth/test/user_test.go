package auth

import (
	"context"
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
	"github.com/ramyadmz/goauth/internal/data"
	"github.com/ramyadmz/goauth/internal/service/auth"
	"github.com/ramyadmz/goauth/internal/service/credentials"
	"github.com/ramyadmz/goauth/pkg/pb"
	"github.com/stretchr/testify/mock"
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

	mockDAL := &MockDAL{}
	mockDAL.On("CreateUser", mock.Anything, mock.Anything).Return(user, nil)

	authService := auth.NewUserAuthService(mockDAL, &MockTokenHandler{})

	_, err := authService.RegisterUser(context.Background(), &pb.RegisterUserRequest{
		Username: user.Username,
		Password: password,
		Email:    user.Email,
	})

	assert.Equal(t, err, nil)
}

func TestRegisterUser_InternalError(t *testing.T) {
	mockDAL := &MockDAL{}
	mockDAL.On("CreateUser", mock.Anything, mock.Anything).Return(&data.User{}, errors.New("Error creating user in database"))

	authService := auth.NewUserAuthService(mockDAL, &MockTokenHandler{})

	_, err := authService.RegisterUser(context.Background(), &pb.RegisterUserRequest{
		Username: mock.Anything,
		Password: mock.Anything,
		Email:    mock.Anything,
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

	mockDAL := &MockDAL{}
	mockDAL.On("GetUserByUsername", mock.Anything, mock.Anything).Return(user, nil)

	mockSessionHandler := &MockTokenHandler{}
	mockSessionHandler.On("Generate", mock.Anything, mock.Anything).Return(sessionID, nil)

	authService := auth.NewUserAuthService(mockDAL, mockSessionHandler)

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

	mockDAL := &MockDAL{}
	mockDAL.On("GetUserByUsername", mock.Anything, mock.Anything).Return(user, nil)

	authService := auth.NewUserAuthService(mockDAL, &MockTokenHandler{})

	_, err := authService.LoginUser(context.Background(), &pb.UserLoginRequest{
		Username: user.Username,
		Password: fakePassword,
	})

	assert.Equal(t, status.Code(err), codes.Unauthenticated)
}

func TestLogoutUser_HappyPath(t *testing.T) {
	mockSessionHandler := &MockTokenHandler{}
	mockSessionHandler.On("Invalidate", mock.Anything, mock.Anything).Return(nil)

	authService := auth.NewUserAuthService(&MockDAL{}, mockSessionHandler)

	_, err := authService.LogoutUser(context.Background(), &pb.UserLogoutRequest{
		SessionId: mock.Anything,
	})

	assert.Equal(t, err, nil)
}

func TestLogoutUser_Unauthenticated(t *testing.T) {
	mockSessionHandler := &MockTokenHandler{}
	mockSessionHandler.On("Invalidate", mock.Anything, mock.Anything).Return(credentials.ErrInvalidToken)

	authService := auth.NewUserAuthService(&MockDAL{}, mockSessionHandler)

	_, err := authService.LogoutUser(context.Background(), &pb.UserLogoutRequest{
		SessionId: mock.Anything,
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

	mockDAL := &MockDAL{}
	mockDAL.On("GetClientByID", mock.Anything, mock.Anything).Return(client, nil)
	mockDAL.On("CreateAuthorization", mock.Anything, mock.Anything, mock.Anything).Return(&data.Authorization{}, nil)

	mockTokenHandler := &MockTokenHandler{}
	mockTokenHandler.On("Validate", mock.Anything, mock.Anything).Return(&credentials.Claims{}, nil)

	authService := auth.NewUserAuthService(mockDAL, mockTokenHandler)
	_, err := authService.ConsentUser(context.Background(), &pb.UserConsentRequest{
		ClientId:  client.ID,
		SessionId: sessionID,
	})

	assert.Equal(t, err, nil)
}

func TestConsentUser_Unauthenticated(t *testing.T) {

	mockTokenHandler := &MockTokenHandler{}
	mockTokenHandler.On("Validate", mock.Anything, mock.Anything).Return(&credentials.Claims{}, credentials.ErrInvalidToken)

	authService := auth.NewUserAuthService(&MockDAL{}, mockTokenHandler)
	_, err := authService.ConsentUser(context.Background(), &pb.UserConsentRequest{
		ClientId:  rand.Int63(),
		SessionId: mock.Anything,
	})

	assert.Equal(t, status.Code(err), codes.Unauthenticated)
}
