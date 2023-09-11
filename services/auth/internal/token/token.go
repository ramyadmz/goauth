package token

type TokenService interface {
	GenerateToken(subject string) (string, error)
	ValidateToken(token string) (bool, error)
}
