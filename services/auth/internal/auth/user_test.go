package auth

import (
	"context"
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
	"github.com/google/uuid"
	"github.com/ramyadmz/goauth/internal/credentials"
	sessionMock "github.com/ramyadmz/goauth/internal/credentials/mock"
	"github.com/ramyadmz/goauth/internal/data"
	dalMock "github.com/ramyadmz/goauth/internal/data/mock"
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

	mockDAL := &dalMock.DataProvider{}
	mockDAL.On("CreateUser", mock.Anything, mock.Anything).Return(user, nil)

	authService := NewUserAuthService(mockDAL, &sessionMock.SessionManager{})

	_, err := authService.RegisterUser(context.Background(), &pb.RegisterUserRequest{
		Username: user.Username,
		Password: password,
		Email:    user.Email,
	})

	assert.Equal(t, err, nil)
}

func TestRegisterUser_InternalError(t *testing.T) {
	mockDAL := &dalMock.DataProvider{}
	mockDAL.On("CreateUser", mock.Anything, mock.Anything).Return(&data.User{}, errors.New("Error creating user in database"))

	authService := NewUserAuthService(mockDAL, &sessionMock.SessionManager{})

	_, err := authService.RegisterUser(context.Background(), &pb.RegisterUserRequest{
		Username: mock.Anything,
		Password: mock.Anything,
		Email:    mock.Anything,
	})

	assert.Equal(t, status.Code(err), codes.Internal)
}

func TestLoginUser_HappyPath(t *testing.T) {
	sessionID := uuid.NewString()
	password := uuid.NewString()
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), 10)
	userID := rand.Int63()
	expiresAt := time.Now().Add(1 * time.Hour)

	user := &data.User{
		ID:             userID,
		Username:       uuid.NewString(),
		HashedPassword: hashedPassword,
		Email:          "user@test.com",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	mockDAL := &dalMock.DataProvider{}
	mockDAL.On("GetUserByUsername", mock.Anything, mock.Anything).Return(user, nil)

	mockSessionManager := &sessionMock.SessionManager{}
	mockSessionManager.On("Start", mock.Anything, mock.Anything).Return(credentials.Session{
		SessionID: sessionID,
		Subject:   userID,
		ExpiresAt: expiresAt,
	}, nil)

	authService := NewUserAuthService(mockDAL, mockSessionManager)

	rsp, err := authService.LoginUser(context.Background(), &pb.UserLoginRequest{
		Username: user.Username,
		Password: password,
	})

	assert.Equal(t, err, nil)
	assert.Equal(t, rsp.SessionId, sessionID)
}

func TestLoginUser_Unauthenticated(t *testing.T) {
	userID := rand.Int63()
	fakePassword := uuid.NewString()
	password := uuid.NewString()
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), 10)

	user := &data.User{
		ID:             userID,
		Username:       uuid.NewString(),
		HashedPassword: hashedPassword,
		Email:          "user102@test.com",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	mockDAL := &dalMock.DataProvider{}
	mockDAL.On("GetUserByUsername", mock.Anything, mock.Anything).Return(user, nil)

	authService := NewUserAuthService(mockDAL, &sessionMock.SessionManager{})

	_, err := authService.LoginUser(context.Background(), &pb.UserLoginRequest{
		Username: user.Username,
		Password: fakePassword,
	})

	assert.Equal(t, status.Code(err), codes.Unauthenticated)
}

func TestLogoutUser_HappyPath(t *testing.T) {
	mockSessionManager := &sessionMock.SessionManager{}
	mockSessionManager.On("End", mock.Anything, mock.Anything).Return(nil)

	authService := NewUserAuthService(&dalMock.DataProvider{}, mockSessionManager)

	_, err := authService.LogoutUser(context.Background(), &pb.UserLogoutRequest{
		SessionId: mock.Anything,
	})

	assert.Equal(t, err, nil)
}

func TestLogoutUser_Unauthenticated(t *testing.T) {
	mockSessionManager := &sessionMock.SessionManager{}
	mockSessionManager.On("End", mock.Anything, mock.Anything).Return(credentials.ErrInvalidSession)

	authService := NewUserAuthService(&dalMock.DataProvider{}, mockSessionManager)

	_, err := authService.LogoutUser(context.Background(), &pb.UserLogoutRequest{
		SessionId: mock.Anything,
	})

	assert.Equal(t, status.Code(err), codes.Unauthenticated)
}

func TestConsentUser_HappyPath(t *testing.T) {
	clientID := rand.Int63()
	clientSecret := uuid.NewString()
	userID := rand.Int63()
	sessionID := uuid.NewString()

	hashedSec, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), 10)
	client := &data.Client{
		ID:           clientID,
		HashedSecret: hashedSec,
		Name:         uuid.NewString(),
		Website:      uuid.NewString(),
		Scope:        "read",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	mockDAL := &dalMock.DataProvider{}
	mockDAL.On("GetClientByID", mock.Anything, mock.Anything).Return(client, nil)
	mockDAL.On("CreateAuthorization", mock.Anything, mock.Anything, mock.Anything).Return(&data.Authorization{}, nil)

	mockSessionManager := &sessionMock.SessionManager{}
	mockSessionManager.On("Get", mock.Anything, mock.Anything).Return(&credentials.Session{
		SessionID: sessionID,
		Subject:   userID,
	}, nil)

	authService := NewUserAuthService(mockDAL, mockSessionManager)
	_, err := authService.ConsentUser(context.Background(), &pb.UserConsentRequest{
		ClientId:  client.ID,
		SessionId: sessionID,
	})

	assert.Equal(t, err, nil)
}

func TestConsentUser_Unauthenticated(t *testing.T) {

	mockSessionManager := &sessionMock.SessionManager{}
	mockSessionManager.On("Get", mock.Anything, mock.Anything).Return(&credentials.Session{}, credentials.ErrInvalidSession)

	authService := NewUserAuthService(&dalMock.DataProvider{}, mockSessionManager)
	_, err := authService.ConsentUser(context.Background(), &pb.UserConsentRequest{
		ClientId:  rand.Int63(),
		SessionId: mock.Anything,
	})

	assert.Equal(t, status.Code(err), codes.Unauthenticated)
}
