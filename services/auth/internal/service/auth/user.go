package auth

import (
	"context"
	"errors"
	"time"

	"github.com/ramyadmz/goauth/internal/data"
	"github.com/ramyadmz/goauth/internal/service/credentials"
	"github.com/ramyadmz/goauth/pkg/pb"
	"github.com/sirupsen/logrus"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	DefaultCost    = 10 // default cost which is passed into GenerateFromPassword hash function
	SessionExpTime = 24 * time.Hour
)

type UserAuthService struct {
	pb.UnimplementedOAuthServiceServer
	DAL            data.AuthProvider
	sessionHandler credentials.TokenHandler
}

func (u *UserAuthService) RegisterUser(ctx context.Context, req *pb.RegisterUserRequest) (*pb.RegisterUserResponse, error) {
	logger := logrus.WithContext(ctx).WithField("username", req.Username).WithField("email", req.Email)
	logger.Info("register request recieved")

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), DefaultCost)
	if err != nil {
		logger.WithField("error", err).Error("Error hashing password")
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	// Create the user
	_, err = u.DAL.CreateUser(ctx, data.CreateUserParams{
		Username:       req.Username,
		HashedPassword: hashedPassword,
		Email:          req.Email,
	})
	if err != nil {
		logger.WithField("error", err).Error("Error creating user in database")
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	// Successful registration
	logger.Info("user registered successfully")
	return &pb.RegisterUserResponse{}, nil
}

func (u *UserAuthService) LoginUser(ctx context.Context, req *pb.UserLoginRequest) (*pb.UserLoginResponse, error) {
	logger := logrus.WithContext(ctx).WithField("username", req.Username)
	logger.Info("login request recieved")

	// Fetch user by username
	userData, err := u.DAL.GetUserByUsername(ctx, req.Username)
	if err != nil {
		if err == data.ErrUserNotFound {
			logger.WithField("error", err).Error("invalid username or password")
			return nil, status.Errorf(codes.Unauthenticated, "invalid username or password")
		}
		logger.WithField("error", err).Error("error retrieving user by username")
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	// Check if the password is correct
	err = bcrypt.CompareHashAndPassword(userData.HashedPassword, []byte(req.Password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			logger.WithField("error", err).Error("invalid username or password")
			return nil, status.Errorf(codes.Unauthenticated, "invalid username or password")
		}
		logger.WithField("error", err).Error("error comparing password")
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	// Generate a new session id
	sessionID, err := u.sessionHandler.Generate(ctx, credentials.Claims{
		Subject:   userData.ID,
		ExpiresAt: time.Now().Add(SessionExpTime),
	})
	if err != nil {
		logger.WithField("error", err).Error("error generating authentication session")
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	// Successful login
	logger.Info("user logged in successfully")
	return &pb.UserLoginResponse{
		SessionId: sessionID,
	}, nil
}

func (u *UserAuthService) LogoutUser(ctx context.Context, req *pb.UserLogoutRequest) (*pb.UserLogoutResponse, error) {
	logger := logrus.WithContext(ctx).WithField("session_id", req.SessionId)
	logger.Info("logout request recieved")

	if err := u.sessionHandler.Invalidate(ctx, req.SessionId); err != nil {
		if err == credentials.ErrInvalidToken {
			logger.WithField("error", err).Error("invalid or expired session")
			return nil, status.Errorf(codes.Unauthenticated, "invalid or expired session")
		}
		logger.WithField("error", err).Error("error validating session")
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	// Successful logout
	logger.Info("user logged out successfully")
	return &pb.UserLogoutResponse{}, nil
}

func (u *UserAuthService) ConsentUser(ctx context.Context, req *pb.UserConsentRequest) (*pb.UserConsentResponse, error) {
	logger := logrus.WithContext(ctx).WithField("session_id", req.SessionId).WithField("client_id", req.ClientId)
	logger.Info("logout request recieved")

	// Validate the token
	userID, err := u.sessionHandler.Validate(ctx, req.SessionId)
	if err != nil {
		if err == credentials.ErrInvalidToken {
			logger.WithField("error", err).Error("invalid or expired session")
			return nil, status.Errorf(codes.Unauthenticated, "invalid or expired session")
		}
		logger.WithField("error", err).Error("error validating session")
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	_ = userID
	// todo check app id existance and create atho code and grant record

	// Successful consent
	logger.Info("user consent successfully")

	return &pb.UserConsentResponse{}, nil
}
