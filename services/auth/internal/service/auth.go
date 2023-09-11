package service

import (
	"context"
	"errors"
	"regexp"

	"github.com/golang-jwt/jwt"
	"github.com/ramyadmz/goauth/internal/config"
	"github.com/ramyadmz/goauth/internal/data"
	"github.com/ramyadmz/goauth/pkg/pb"
	"github.com/ramyadmz/goauth/internal/token/pb"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	EmailRegexPattern = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	DefaultCost       = 10 // default cost which is passed into GenerateFromPassword hash function
)

type AuthService struct {
	pb.UnimplementedAuthServiceServer
	DAL    data.AuthProvider
	??? token.jwt.JWTSerive
}

func (as *AuthService) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	err := as.validateRegisterRequest(req)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "request data is invalid: %v", err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), DefaultCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to hash password: %v", err)

	}

	_, err = as.DAL.CreateUser(ctx, data.CreateUseParams{Username: req.Username, Password: string(hashedPassword), Email: req.Email})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to insert user data to database: %v", err)
	}

	token, err := as.(req.Username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate token: %v", err)
	}

	return &pb.RegisterResponse{
		Success: true,
		Message: "",
		Token:   token,
	}, nil
}

func (as *AuthService) validateRegisterRequest(req *pb.RegisterRequest) error {
	if !isValidEmail(req.Email) {
		return errors.New("invalid email format")
	}

	if !isValidPassword(req.Password) {
		return errors.New("password must be at least 8 characters long")
	}

	if !isValidUsername(req.Username) {
		return errors.New("username must be between 3 and 20 characters")
	}

	return nil
}

func isValidEmail(email string) bool {
	return regexp.MustCompile(EmailRegexPattern).MatchString(email)
}

func isValidUsername(username string) bool {
	return len(username) > 4 && len(username) < 20
}

func isValidPassword(password string) bool {
	return len(password) >= 8
}
