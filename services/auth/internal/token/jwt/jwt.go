package jwt

import (
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/ramyadmz/goauth/internal/config"
)

type JWTService struct {
	config *config.JWTConfig
}

func NewJWTService(cnfg *config.JWTConfig) *JWTService {
	return &JWTService{
		config: cnfg,
	}
}

func (js *JWTService) GenerateToken(subject string) (string, error) {
	claims := jwt.StandardClaims{
		Subject:   subject,
		Issuer:    js.config,
		IssuedAt:  
		ExpiresAt: time.Now().Add(72 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwtService.config.GetSigningMethod(), claims)
	return token.SignedString([]byte(jwtService.config.GetSecretKey()))
}
