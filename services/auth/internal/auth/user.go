package auth

import (
	"context"
	"errors"
	"time"

	"github.com/ramyadmz/goauth/internal/credentials"
	"github.com/ramyadmz/goauth/internal/data"
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
	dal            data.DataProvider
	sessionManager credentials.SessionManager
}

// NewUserAuthService creates a new instance of ClientAuthService with the provided dependencies.
func NewUserAuthService(dal data.DataProvider, sessionManager credentials.SessionManager) *UserAuthService {
	return &UserAuthService{
		dal:            dal,
		sessionManager: sessionManager,
	}
}

func (u *UserAuthService) RegisterUser(ctx context.Context, req *pb.RegisterUserRequest) (*pb.RegisterUserResponse, error) {
	logger := logrus.WithContext(ctx).WithField("username", req.Username).WithField("email", req.Email)
	logger.Info("register request recieved")

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), DefaultCost)
	if err != nil {
		logger.Error("Error hashing password: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	// Create the user
	_, err = u.dal.CreateUser(ctx, data.CreateUserParams{
		Username:       req.Username,
		HashedPassword: hashedPassword,
		Email:          req.Email,
	})
	if err != nil {
		logger.Error("Error creating user in database: %w", err)
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
	userData, err := u.dal.GetUserByUsername(ctx, req.Username)
	if err != nil {
		if err == data.ErrUserNotFound {
			logger.Error("invalid username or password: %w", err)
			return nil, status.Errorf(codes.Unauthenticated, "invalid username or password")
		}
		logger.Error("error retrieving user by username: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	// Check if the password is correct
	err = bcrypt.CompareHashAndPassword(userData.HashedPassword, []byte(req.Password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			logger.Error("invalid username or password: %w", err)
			return nil, status.Errorf(codes.Unauthenticated, "invalid username or password")
		}
		logger.Error("error comparing password: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	// Generate a new session id
	session, err := u.sessionManager.Start(ctx, userData.ID)
	if err != nil {
		logger.Error("error generating authentication session: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	// Successful login
	logger.Info("user logged in successfully")
	return &pb.UserLoginResponse{
		SessionId: session.SessionID,
	}, nil
}

func (u *UserAuthService) LogoutUser(ctx context.Context, req *pb.UserLogoutRequest) (*pb.UserLogoutResponse, error) {
	logger := logrus.WithContext(ctx).WithField("session_id", req.SessionId)
	logger.Info("logout request recieved")

	if err := u.sessionManager.End(ctx, req.SessionId); err != nil {
		if err == credentials.ErrInvalidSession {
			logger.Error("invalid or expired session: %w", err)
			return nil, status.Errorf(codes.Unauthenticated, "invalid or expired session")
		}
		logger.Error("error validating session: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	// Successful logout
	logger.Info("user logged out successfully")
	return &pb.UserLogoutResponse{}, nil
}

func (u *UserAuthService) ConsentUser(ctx context.Context, req *pb.UserConsentRequest) (*pb.UserConsentResponse, error) {
	logger := logrus.WithContext(ctx).WithField("session_id", req.SessionId).WithField("client_id", req.ClientId)
	logger.Info("consent request recieved")

	// Validate the token
	claims, err := u.sessionManager.Get(ctx, req.SessionId)
	if err != nil {
		if err == credentials.ErrInvalidSession {
			logger.Error("invalid or expired session: %w", err)
			return nil, status.Errorf(codes.Unauthenticated, "invalid or expired session")
		}
		logger.Error("error validating session: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	client, err := u.dal.GetClientByID(ctx, req.ClientId)
	if err != nil {
		if err == data.ErrClientNotFound {
			logger.Warn("client doesnt exist")
			return nil, status.Errorf(codes.InvalidArgument, "client doesn't exist")
		}
		logger.Error("error validating client: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	_, err = u.dal.CreateAuthorization(ctx, data.CreateAuthorizationParams{
		UserID:   claims.Subject.(int64),
		ClientID: client.ID,
		Scope:    "", // todo add scope
	})

	if err != nil {
		logger.Error("error creating authorization: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	// Successful consent
	logger.Info("user consent successfully")
	return &pb.UserConsentResponse{}, nil
}
