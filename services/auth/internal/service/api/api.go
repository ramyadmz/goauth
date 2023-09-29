package api

// import (
// 	"context"
// 	"errors"

// 	"github.com/go-playground/validator/v10"
// 	"github.com/ramyadmz/goauth/internal/data"
// 	"github.com/ramyadmz/goauth/internal/service/credentials"
// 	"github.com/ramyadmz/goauth/pkg/pb"

// 	"golang.org/x/crypto/bcrypt"
// 	"google.golang.org/grpc"
// 	"google.golang.org/grpc/codes"
// 	"google.golang.org/grpc/status"
// )

// const (
// 	DefaultCost = 10 // default cost which is passed into GenerateFromPassword hash function
// )

// type APIAuthService struct {
// 	pb.un
// 	DAL          data.AuthProvider
// 	tokenHandler credentials.TokenHandler
// }

// func (a *APIAuthService) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
// 	// Hash the password
// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), DefaultCost)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Internal, "Error hashing password: %v", err)
// 	}

// 	// Create the user
// 	userData, err := a.DAL.CreateUser(ctx, data.CreateUseParams{
// 		Username: req.Username,
// 		Password: hashedPassword,
// 		Email:    req.Email,
// 	})
// 	if err != nil {
// 		return nil, status.Errorf(codes.Internal, "Error creating user in database: %v", err)
// 	}

// 	// Generate a new token
// 	token, err := a.tokenHandler.Generate(userData.ID)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Internal, "Error generating authentication token: %v", err)
// 	}

// 	// Successful registration
// 	return &pb.RegisterResponse{
// 		Success: true,
// 		Message: "Registration successful",
// 		Token:   token,
// 	}, nil
// }

// func (a *APIAuthService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
// 	// Fetch user by username
// 	userData, err := a.DAL.GetUserByUsername(ctx, req.Username)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Internal, "Error retrieving user by username: %v", err)
// 	}

// 	// Check if the password is correct
// 	err = bcrypt.CompareHashAndPassword(userData.Password, []byte(req.Password))
// 	if err != nil {
// 		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
// 			return nil, status.Error(codes.Unauthenticated, "Invalid credentials")
// 		}
// 		return nil, status.Errorf(codes.Internal, "Error comparing password: %v", err)
// 	}

// 	// Generate a new token
// 	token, err := a.tokenHandler.Generate(userData.ID)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Internal, "Error generating authentication token: %v", err)
// 	}

// 	// Successful login
// 	return &pb.LoginResponse{
// 		Success: true,
// 		Message: "Login successful",
// 		Token:   token,
// 	}, nil
// }

// func (a *APIAuthService) Validate(ctx context.Context, req *pb.ValidateRequest) (*pb.ValidateResponse, error) {
// 	// Validate the token
// 	userID, err := a.tokenHandler.Validate(req.Token)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Unauthenticated, "Invalid token: %v", err)
// 	}

// 	// Check if the user exists
// 	_, err = a.DAL.GetUserByID(ctx, userID.(string))
// 	if err != nil {
// 		return &pb.ValidateResponse{
// 			IsValid: false,
// 			Subject: "User not found",
// 		}, nil
// 	}

// 	return &pb.ValidateResponse{
// 		IsValid: true,
// 	}, nil
// }

// func ValidationInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
// 	switch info.FullMethod {
// 	case "/pb.AuthService/Register":
// 		if err := validateRegisterRequest(req.(*pb.RegisterRequest)); err != nil {
// 			return nil, status.Errorf(codes.InvalidArgument, "invalid register request: %v", err)
// 		}
// 	case "/pb.AuthService/Validate":
// 		if err := validateValidateRequest(req.(*pb.ValidateRequest)); err != nil {
// 			return nil, status.Errorf(codes.InvalidArgument, "invalid validate request: %v", err)
// 		}
// 	}
// 	return handler(ctx, req)
// }

// func validateRegisterRequest(req *pb.RegisterRequest) error {
// 	validate := validator.New()
// 	if err := validate.Var(req.Email, "required,email"); err != nil {
// 		return err
// 	}

// 	if err := validate.Var(req.Password, "required,min=8"); err != nil {
// 		return err
// 	}

// 	if err := validate.Var(req.Username, "required,min=3,max=20"); err != nil {
// 		return err
// 	}

// 	return nil
// }

// func validateValidateRequest(req *pb.ValidateRequest) error {
// 	validate := validator.New()
// 	if err := validate.Var(req.Token, "required,min=70"); err != nil {
// 		return err
// 	}
// 	return nil
// }
