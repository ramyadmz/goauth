package auth

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
	case "/pb.OAuthService/RegisterUser":
		if err := validateRegisterUserRequest(req.(*pb.RegisterUserRequest)); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid register request: %v", err)
		}
	case "/pb.OAuthService/UserLogin":
		if err := validateUserLoginRequest(req.(*pb.UserLoginRequest)); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid login request: %v", err)
		}
	case "/pb.OAuthService/UserConsent":
		if err := validateUserConsentRequest(req.(*pb.UserConsentRequest)); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid consent request: %v", err)
		}
	case "/pb.OAuthService/UserLogout":
		if err := validateUserLogoutRequest(req.(*pb.UserLogoutRequest)); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid login request: %v", err)
		}
	case "/pb.OAuthService/RegisterClient":
		if err := validateRegisterClientRequest(req.(*pb.RegisterClientRequest)); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid register request: %v", err)
		}
	case "/pb.OAuthService/GetAuthorizationCode":
		if err := validateGetAuthorizationCodeRequest(req.(*pb.GetAuthorizationCodeRequest)); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid login request: %v", err)
		}
	case "/pb.OAuthService/ExchangeToken":
		if err := validateExchangeTokenRequest(req.(*pb.ExchangeTokenRequest)); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid consent request: %v", err)
		}
	case "/pb.OAuthService/RefreshToken":
		if err := validateRefreshTokenRequest(req.(*pb.RefreshTokenRequest)); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid login request: %v", err)
		}
	}
	return handler(ctx, req)
}

func validateRegisterUserRequest(req *pb.RegisterUserRequest) error {
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

func validateUserLoginRequest(req *pb.UserLoginRequest) error {
	validate := validator.New()
	if err := validate.Var(req.Username, "required,min=3,max=20"); err != nil {
		return err
	}

	if err := validate.Var(req.Password, "required,min=8"); err != nil {
		return err
	}

	return nil
}

func validateUserConsentRequest(req *pb.UserConsentRequest) error {
	validate := validator.New()
	if err := validate.Var(req.ClientId, "required,min=4"); err != nil {
		return err
	}
	if err := validate.Var(req.SessionId, "required,min=4"); err != nil {
		return err
	}

	return nil
}

func validateUserLogoutRequest(req *pb.UserLogoutRequest) error {
	validate := validator.New()
	if err := validate.Var(req.SessionId, "required,min=4"); err != nil {
		return err
	}

	return nil
}

func validateRegisterClientRequest(req *pb.RegisterClientRequest) error {
	validate := validator.New()
	if err := validate.Var(req.Name, "required,min=4"); err != nil {
		return err
	}

	if err := validate.Var(req.Website, "required,min=5"); err != nil {
		return err
	}

	if err := validate.Var(req.Scope, "required,min=4"); err != nil {
		return err
	}

	return nil
}

func validateGetAuthorizationCodeRequest(req *pb.GetAuthorizationCodeRequest) error {
	validate := validator.New()
	if err := validate.Var(req.ClientId, "required,min=4"); err != nil {
		return err
	}

	if err := validate.Var(req.ClientSecret, "required,min=8"); err != nil {
		return err
	}

	if err := validate.Var(req.Username, "required,min=4,max=20"); err != nil {
		return err
	}

	return nil
}

func validateExchangeTokenRequest(req *pb.ExchangeTokenRequest) error {
	validate := validator.New()
	if err := validate.Var(req.ClientId, "required,min=4"); err != nil {
		return err
	}

	if err := validate.Var(req.ClientSecret, "required,min=8"); err != nil {
		return err
	}

	if err := validate.Var(req.AuthorizationCode, "required,min=8"); err != nil {
		return err
	}

	return nil
}

func validateRefreshTokenRequest(req *pb.RefreshTokenRequest) error {
	validate := validator.New()
	if err := validate.Var(req.RefreshToken, "required,jwt"); err != nil {
		return err
	}

	return nil
}
