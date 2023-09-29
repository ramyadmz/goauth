package user

import (
	"context"
	"errors"

	"github.com/ramyadmz/goauth/internal/data"
	"github.com/ramyadmz/goauth/internal/service/credentials"
	"github.com/ramyadmz/goauth/pkg/pb"

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
	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), DefaultCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error hashing password: %v", err)
	}

	// Create the user
	userData, err := u.DAL.CreateUser(ctx, data.CreateUserParams{
		Username:       req.Username,
		HashedPassword: hashedPassword,
		Email:          req.Email,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error creating user in database: %v", err)
	}

	// Generate a new session id
	sessionId, err := u.sessionHandler.Generate(ctx, userData.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error generating authentication session id: %v", err)
	}

	// Successful registration
	return &pb.RegisterResponse{
		SessionId: sessionId,
	}, nil
}

func (u *UserAuthService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	// Fetch user by username
	userData, err := u.DAL.GetUserByUsername(ctx, req.Username)
	if err != nil {
		if err == data.ErrUserNotFound {
			return nil, status.Errorf(codes.Unauthenticated, "Invalid username or password.")
		}
		return nil, status.Errorf(codes.Internal, "Error retrieving user by username: %v", err)
	}

	// Check if the password is correct
	err = bcrypt.CompareHashAndPassword(userData.HashedPassword, []byte(req.Password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return nil, status.Errorf(codes.Unauthenticated, "Invalid username or password.")
		}
		return nil, status.Errorf(codes.Internal, "Error comparing password: %v", err)
	}

	// Generate a new session id
	sessionId, err := u.sessionHandler.Generate(ctx, userData.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error generating authentication session: %v", err)
	}

	// Successful login
	return &pb.LoginResponse{
		SessionId: sessionId,
	}, nil
}

func (u *UserAuthService) Consent(ctx context.Context, req *pb.ConsentRequest) (*pb.ConsentResponse, error) {
	// Validate the token
	userID, err := u.sessionHandler.Validate(ctx, req.SessionId)
	if err != nil {
		if err == credentials.ErrInvalidToken {
			return nil, status.Errorf(codes.Unauthenticated, "Invalid or expired session.")
		}
		return nil, status.Errorf(codes.Internal, "Error validating session: %v", err)
	}

	// Check if the user exists
	userData, err := u.DAL.GetUserByID(ctx, userID.(int))
	if err != nil {
		if err == data.ErrUserNotFound {
			return nil, status.Errorf(codes.Unauthenticated, "Invalid session.")
		}
		return nil, status.Errorf(codes.Internal, "Error retrieving user by user id: %v", err)
	}

	// Check if the username is matched with associated session username
	if req.Username != userData.Username {
		return nil, status.Errorf(codes.Unauthenticated, "Invalid session.")
	}

	// todo check app id existance and create atho code and grant record

	return &pb.ConsentResponse{}, nil
}
