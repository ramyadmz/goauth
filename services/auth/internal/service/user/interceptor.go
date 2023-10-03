package user

import (
	"context"

	"github.com/go-playground/validator/v10"
	"github.com/ramyadmz/goauth/pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func ValidationInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	switch info.FullMethod {
	case "/pb.AuthService/Register":
		if err := validateRegisterRequest(req.(*pb.RegisterRequest)); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid register request: %v", err)
		}
	case "/pb.AuthService/Login":
		if err := validateLoginRequest(req.(*pb.LoginRequest)); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid login request: %v", err)
		}
	case "/pb.AuthService/Consent":
		if err := validateConsentRequest(req.(*pb.ConsentRequest)); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid consent request: %v", err)
		}
	case "/pb.AuthService/Logout":
		if err := validateLogoutRequest(req.(*pb.LogoutRequest)); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid login request: %v", err)
		}
	}
	return handler(ctx, req)
}

func validateRegisterRequest(req *pb.RegisterRequest) error {
	validate := validator.New()
	if err := validate.Var(req.Email, "required,email"); err != nil {
		return err
	}

	if err := validate.Var(req.Username, "required,min=4,max=20"); err != nil {
		return err
	}

	if err := validate.Var(req.Password, "required,min=8"); err != nil {
		return err
	}

	return nil
}

func validateLoginRequest(req *pb.LoginRequest) error {
	validate := validator.New()
	if err := validate.Var(req.Username, "required,min=3,max=20"); err != nil {
		return err
	}

	if err := validate.Var(req.Password, "required,min=8"); err != nil {
		return err
	}

	return nil
}

func validateConsentRequest(req *pb.ConsentRequest) error {
	validate := validator.New()
	if err := validate.Var(req.ClientId, "required,min=4"); err != nil {
		return err
	}
	if err := validate.Var(req.SessionId, "required,min=4"); err != nil {
		return err
	}

	return nil
}

func validateLogoutRequest(req *pb.LogoutRequest) error {
	validate := validator.New()
	if err := validate.Var(req.SessionId, "required,min=4"); err != nil {
		return err
	}

	return nil
}
