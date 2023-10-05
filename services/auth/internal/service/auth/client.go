package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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
	AccessTokenExp  = 1 * time.Hour
	RefreshTokenExp = 24 * time.Hour
)

type ClientAuthService struct {
	pb.UnimplementedOAuthServiceServer
	dal          data.AuthProvider
	tokenHandler credentials.TokenHandler
}

// NewClientAuthService creates a new instance of ClientAuthService with the provided dependencies.
func NewClientAuthService(dal data.AuthProvider, tokenHandler credentials.TokenHandler) *ClientAuthService {
	return &ClientAuthService{
		dal:          dal,
		tokenHandler: tokenHandler,
	}
}

func (c *ClientAuthService) RegisterClient(ctx context.Context, req *pb.RegisterClientRequest) (*pb.RegisterClientResponse, error) {
	logger := logrus.WithContext(ctx).WithField("name", req.Name).WithField("website", req.Website).WithField("scope", req.Scope)

	secret, err := generateSecret(ctx)
	if err != nil {
		logger.Error("error generating secret: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(secret), 10)
	if err != nil {
		logger.Error("Error hashing secret: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	clientData, err := c.dal.CreateClient(ctx, data.CreateClientParams{
		Name:         req.Name,
		Website:      req.Website,
		Scope:        req.Scope,
		HashedSecret: string(hashedSecret),
	})

	if err != nil {
		logger.Error("Error creating client: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	logger.Info("client registered successfully")
	return &pb.RegisterClientResponse{
		ClientId:     clientData.ID,
		ClientSecret: secret,
	}, nil

}

func (c *ClientAuthService) GetAuthorizationCode(ctx context.Context, req *pb.GetAuthorizationCodeRequest) (*pb.GetAuthorizationCodeResponse, error) {
	logger := logrus.WithContext(ctx).WithField("clientID", req.ClientId).WithField("username", req.Username)

	client, err := c.dal.GetClientByID(ctx, req.ClientId)
	if err != nil {
		if err == data.ErrClientNotFound {
			logger.Warn("Invalid client id: %w", err)
			return nil, status.Errorf(codes.Unauthenticated, "invalid client id or secret")
		}
		logger.Error("error failed to fetch client by client id: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	err = bcrypt.CompareHashAndPassword(client.HashedSecret, []byte(req.ClientSecret))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			logger.Warn("invalid client secret: %w", err)
			return nil, status.Errorf(codes.Unauthenticated, "invalid client id or secret")
		}
		logger.Error("error comparing client secret and hashed secret: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	user, err := c.dal.GetUserByUsername(ctx, req.Username)
	if err != nil {
		if err == data.ErrClientNotFound {
			logger.Warn("invalid username: %w", err)
			return nil, status.Errorf(codes.Unauthenticated, "invalid username")
		}
		logger.Error("error failed to fetch user by username: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	auth, err := c.dal.GetAuthorizationCodeByUserIDAndClientID(ctx, user.ID, req.ClientId)
	if err != nil {
		if err == data.ErrAuthorizationNotFound {
			logger.Warn("auth not found: %w", err)
			return nil, status.Errorf(codes.Unauthenticated, "Authorization record not found.")
		}
		logger.Error("error failed to fetch authorization record: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	logger.Info("authorization code returned successfully")
	return &pb.GetAuthorizationCodeResponse{
		AuthorizationCode: auth.AuthCode,
	}, nil
}

func (c *ClientAuthService) ExchangeToken(ctx context.Context, req *pb.ExchangeTokenRequest) (*pb.ExchangeTokenResponse, error) {
	logger := logrus.WithContext(ctx).WithField("clientID", req.ClientId)

	client, err := c.dal.GetClientByID(ctx, req.ClientId)
	if err != nil {
		if err == data.ErrClientNotFound {
			logger.Warn("Invalid client id: %w", err)
			return nil, status.Errorf(codes.Unauthenticated, "invalid client id or secret")
		}
		logger.Error("error failed to fetch client by client id: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	err = bcrypt.CompareHashAndPassword(client.HashedSecret, []byte(req.ClientSecret))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			logger.Warn("invalid client secret: %w", err)
			return nil, status.Errorf(codes.Unauthenticated, "invalid client id or secret")
		}
		logger.Error("error comparing client secret and hashed secret: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	auth, err := c.dal.GetAuthorizationCodeByAuthCode(ctx, req.AuthorizationCode)
	if err != nil {
		if err == data.ErrAuthorizationNotFound {
			logger.Warn("Invalid auth code: %w", err)
			return nil, status.Errorf(codes.Unauthenticated, "invalid auth code")
		}
		logger.Error("error failed to fetch authorization by auth code: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	if auth.ClientID != req.ClientId {
		logger.Warnf("Mismatched Client IDs: auth.ClientID = %d, req.ClientID = %d", auth.ClientID, req.ClientId)
		return nil, status.Errorf(codes.Unauthenticated, "Invalid authorization code.")
	}

	accessToken, err := c.tokenHandler.Generate(ctx, credentials.Claims{
		Subject:   auth.UserID,
		ExpiresAt: time.Now().Add(AccessTokenExp),
	})

	if err != nil {
		logger.Error("error failed to generate access token: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	refreshToken, err := c.tokenHandler.Generate(ctx, credentials.Claims{
		Subject:   auth.UserID,
		ExpiresAt: time.Now().Add(RefreshTokenExp),
	})

	if err != nil {
		logger.Error("error failed to generate refresh token: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	logger.Info("access and refresh token returned successfully")
	return &pb.ExchangeTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (c *ClientAuthService) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	logger := logrus.WithContext(ctx).WithField("refreshToken", req.RefreshToken)

	claims, err := c.tokenHandler.Validate(ctx, req.RefreshToken)

	if err != nil {
		if errors.Is(err, credentials.ErrInvalidToken) {
			logger.Warn("Invalid refresh token: %w", err)
			return nil, status.Errorf(codes.Unauthenticated, "Invalid refresh token.")
		} else {
			logger.Error("error failed to validate refresh token: %w", err)
			return nil, status.Errorf(codes.Internal, "Internal server error")
		}
	}

	accessToken, err := c.tokenHandler.Generate(ctx, credentials.Claims{
		Subject:   claims.Subject,
		ExpiresAt: time.Now().Add(AccessTokenExp),
	})

	if err != nil {
		logger.Error("error failed to generate access token: %w", err)
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	logger.Info("access token refreshed successfully")
	return &pb.RefreshTokenResponse{
		AccessToken: accessToken,
	}, nil
}

func generateSecret(ctx context.Context) (string, error) {
	secretBytes := make([]byte, 32)
	_, err := rand.Read(secretBytes)
	if err != nil {
		return "", credentials.ErrGeneratingSecret
	}
	return base64.URLEncoding.EncodeToString(secretBytes), nil
}
