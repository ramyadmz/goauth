package user

import (
	"context"
	"errors"

	"github.com/ramyadmz/goauth/internal/data"
	"github.com/ramyadmz/goauth/internal/service/credentials"
	"github.com/ramyadmz/goauth/pkg/pb"
	"github.com/sirupsen/logrus"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	DefaultCost = 10 // default cost which is passed into GenerateFromPassword hash function
)

type UserAuthService struct {
	pb.UnimplementedUserAuthServiceServer
	DAL            data.AuthProvider
	sessionHandler credentials.TokenHandler
}

func (u *UserAuthService) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	logger := logrus.WithContext(ctx).WithField("username", req.Username).WithField("email", req.Email)
	logger.Info("register request recieved")

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), DefaultCost)
	if err != nil {
		logger.WithField("error", err).Error("Error hashing password")
		return nil, status.Errorf(codes.Internal, "Error hashing password: %v", err)
	}

	// Create the user
	_, err = u.DAL.CreateUser(ctx, data.CreateUserParams{
		Username:       req.Username,
		HashedPassword: hashedPassword,
		Email:          req.Email,
	})
	if err != nil {
		logger.WithField("error", err).Error("Error creating user in database")
		return nil, status.Errorf(codes.Internal, "Error creating user in database: %v", err)
	}

	// Successful registration
	logger.Info("user registered successfully")
	return &pb.RegisterResponse{}, nil
}

func (u *UserAuthService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
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
		return nil, status.Errorf(codes.Internal, "error retrieving user by username: %v", err)
	}

	// Check if the password is correct
	err = bcrypt.CompareHashAndPassword(userData.HashedPassword, []byte(req.Password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			logger.WithField("error", err).Error("invalid username or password")
			return nil, status.Errorf(codes.Unauthenticated, "invalid username or password")
		}
		logger.WithField("error", err).Error("error comparing password")
		return nil, status.Errorf(codes.Internal, "error comparing password: %v", err)
	}

	// Generate a new session id
	sessionID, err := u.sessionHandler.Generate(ctx, userData.ID)
	if err != nil {
		logger.WithField("error", err).Error("error generating authentication session")
		return nil, status.Errorf(codes.Internal, "error generating authentication session: %v", err)
	}

	// Successful login
	logger.Info("user logged in successfully")
	return &pb.LoginResponse{
		SessionId: sessionID,
	}, nil
}

func (u *UserAuthService) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	logger := logrus.WithContext(ctx).WithField("session_id", req.SessionId)
	logger.Info("logout request recieved")

	_, err := u.sessionHandler.Invalidate(ctx, req.SessionId)
	if err != nil {
		if err == credentials.ErrInvalidToken {
			logger.WithField("error", err).Error("invalid or expired session")
			return nil, status.Errorf(codes.Unauthenticated, "invalid or expired session")
		}
		logger.WithField("error", err).Error("error validating session")
		return nil, status.Errorf(codes.Internal, "error validating session: %v", err)
	}

	// Successful logout
	logger.Info("user logged out successfully")
	return &pb.LogoutResponse{}, nil
}

func (u *UserAuthService) Consent(ctx context.Context, req *pb.ConsentRequest) (*pb.ConsentResponse, error) {
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
		return nil, status.Errorf(codes.Internal, "error validating session: %v", err)
	}

	_ = userID
	// todo check app id existance and create atho code and grant record

	// Successful consent
	logger.Info("user consent successfully")

	return &pb.ConsentResponse{}, nil
}
