package postgres

import (
	"context"
	"time"

	"github.com/go-pg/pg/v11"
	"github.com/google/uuid"
	"github.com/ramyadmz/goauth/internal/data"
	"github.com/sirupsen/logrus"
)

// PostgresProvider implements the AuthProvider interface using PostgreSQL as a backend.
type PostgresProvider struct {
	db *pg.DB
}

// Compile-time check to ensure PostgresProvider satisfies the data.AuthProvider interface.
var _ data.AuthProvider = new(PostgresProvider)

// CreateUser creates a new user in the database.
func (p *PostgresProvider) CreateUser(ctx context.Context, params data.CreateUserParams) (*data.User, error) {
	logger := logrus.WithContext(ctx).WithField("username", params.Username).WithField("email", params.Email)
	user := &User{
		Username:       params.Username,
		HashedPassword: params.HashedPassword,
		Email:          params.Email,
	}

	_, err := p.db.Model(user).Insert(ctx)
	if err != nil {
		logger.WithField("error", err).Error("Error creating user")
		return nil, data.ErrUserCreation
	}

	logger.Info("user created successfully")
	return user.ToData(), nil
}

// GetUserByID retrieves a user by their ID from the database.
func (p *PostgresProvider) GetUserByID(ctx context.Context, userID int64) (*data.User, error) {
	logger := logrus.WithContext(ctx).WithField("userID", userID)
	user := &User{ID: userID}

	err := p.db.Model(user).WherePK().Select(ctx)
	if err != nil {
		if err == pg.ErrNoRows {
			logger.WithField("error", err).Error(data.ErrUserNotFound)
			return nil, data.ErrUserNotFound
		}
		logger.WithField("error", err).Error("error fetching user by userid")
		return nil, err
	}

	logger.Info("user fetched by id successfully")
	return user.ToData(), nil
}

func (p *PostgresProvider) GetUserByUsername(ctx context.Context, username string) (*data.User, error) {
	logger := logrus.WithContext(ctx).WithField("username", username)
	user := &User{Username: username}

	err := p.db.Model(user).Select(ctx)
	if err != nil {
		if err == pg.ErrNoRows {
			logger.WithField("error", err).Error(data.ErrUserNotFound)
			return nil, data.ErrUserNotFound
		}
		logger.WithField("error", err).Error("error fetching user by username")
		return nil, err
	}

	logger.Info("user fetched by username successfully")
	return user.ToData(), nil
}

// CreateSession creates a new session in the database.
func (p *PostgresProvider) CreateSession(ctx context.Context, params data.CreateSessionParams) (*data.Session, error) {
	logger := logrus.WithContext(ctx).WithField("userID", params.UserID)
	session := &Session{
		ID:        uuid.NewString(),
		UserID:    params.UserID,
		ExpiresAt: params.ExpiresAt,
	}

	_, err := p.db.Model(session).Insert(ctx)
	if err != nil {
		logger.WithField("error", err).Error(data.ErrSessionCreation)
		return nil, data.ErrSessionCreation
	}

	logger.Info("session created successfully")
	return session.ToData(), nil
}

// GetSessionByID retrieves a session by ID from the database.
func (p *PostgresProvider) GetSessionByID(ctx context.Context, sessionID string) (*data.Session, error) {
	logger := logrus.WithContext(ctx).WithField("sessionID", sessionID)
	session := &Session{
		ID: sessionID,
	}

	err := p.db.Model(session).WherePK().Select(ctx)
	if err != nil {
		if err == pg.ErrNoRows {
			logger.WithField("error", err).Error(data.ErrSessionNotFound)
			return nil, data.ErrSessionNotFound
		}
		logger.WithField("error", err).Error("error fetching session by session id")
		return nil, err
	}

	logger.Info("session fetched successfully")
	return session.ToData(), nil
}

func (p *PostgresProvider) DeleteSessionByID(ctx context.Context, sessionID string) error {
	logger := logrus.WithContext(ctx).WithField("sessionID", sessionID)
	session := &Session{ID: sessionID}

	_, err := p.db.Model(session).Delete(ctx)
	if err != nil {
		logger.WithField("error", err).Error("error deleting session by session id")
		return err
	}

	logger.Info("session deleted successfully")
	return nil
}

func (p *PostgresProvider) UpdateSession(ctx context.Context, params data.UpdateSessionParams) (*data.Session, error) {
	logger := logrus.WithContext(ctx).WithField("sessionID", params.SessionID).WithField("expireDate", params.ExpiresAt)
	session := &Session{
		ID:        params.SessionID,
		ExpiresAt: params.ExpiresAt,
	}

	_, err := p.db.Model(session).UpdateNotZero(ctx)
	if err != nil {
		logger.WithField("error", err).Error("error updating session")
		return nil, err
	}

	logger.Info("session updated successfully")
	return session.ToData(), nil
}

func (p *PostgresProvider) CreateClient(ctx context.Context, params data.CreateClientParams) (*data.Client, error) {
	logger := logrus.WithContext(ctx).WithField("clientName", params.Name).WithField("scope", params.Scope)

	client := &Client{
		Name:         params.Name,
		HashedSecret: []byte(params.HashedSecret),
		Website:      params.Website,
		Scope:        params.Scope,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	_, err := p.db.Model(client).Returning("id").Insert(ctx)
	if err != nil {
		logger.WithField("error", err).Error("error creating client")
		return nil, err
	}

	logger.Info("client created successfully")
	return client.ToData(), nil
}

func (p *PostgresProvider) GetClientByID(ctx context.Context, clientID int64) (*data.Client, error) {
	logger := logrus.WithContext(ctx).WithField("clientID", clientID)
	client := &Client{
		ID: clientID,
	}

	err := p.db.Model(client).Select(ctx)
	if err != nil {
		if err == pg.ErrNoRows {
			logger.WithField("error", err).Error(data.ErrClientNotFound)
			return nil, data.ErrClientNotFound
		}
		logger.WithField("error", err).Error("error fetching client")
		return nil, err
	}

	logger.Info("client fetched successfully")
	return client.ToData(), nil
}

func (p *PostgresProvider) CreateAuthorization(ctx context.Context, params data.CreateAuthorizationParams) (*data.Authorization, error) {
	logger := logrus.WithContext(ctx).WithField("clientID", params.ClientID).WithField("userID", params.UserID).WithField("scope", params.Scope)
	authorization := &Authorization{
		AuthCode:  uuid.NewString(),
		ClientID:  params.ClientID,
		UserID:    params.UserID,
		Scope:     params.Scope,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	_, err := p.db.Model(authorization).Insert(ctx)
	if err != nil {
		logger.WithField("error", err).Error("error creating authorization")
		return nil, err
	}

	logger.Info("authorization created successfully")
	return authorization.ToData(), nil
}

func (p *PostgresProvider) GetAuthorizationCodeByAuthCode(ctx context.Context, authCode string) (*data.Authorization, error) {
	logger := logrus.WithContext(ctx)
	authorization := &Authorization{
		AuthCode: authCode,
	}

	err := p.db.Model(authorization).Select(ctx)
	if err != nil {
		if err == pg.ErrNoRows {
			logger.Warn("invalid auth code: %w", err)
			return nil, data.ErrAuthorizationNotFound
		}
		logger.WithField("error", err).Error("error fetching authorization")
		return nil, err
	}

	logger.Info("authorization fetched successfully")
	return authorization.ToData(), nil
}

func (p *PostgresProvider) GetAuthorizationCodeByUserIDAndClientID(ctx context.Context, userID, clientID int64) (*data.Authorization, error) {
	logger := logrus.WithContext(ctx).WithField("userID", userID).WithField("clientID", clientID)
	authorization := &Authorization{
		ClientID: clientID,
		UserID:   userID,
	}

	err := p.db.Model(authorization).Select(ctx)
	if err != nil {
		if err == pg.ErrNoRows {
			logger.WithField("error", err).Error(data.ErrAuthorizationNotFound)
			return nil, data.ErrAuthorizationNotFound
		}
		logger.WithField("error", err).Error("error fetching authorization")
		return nil, err
	}

	logger.Info("authorization fetched successfully")
	return authorization.ToData(), nil
}

func (p *PostgresProvider) RevokeAuthorizationByUserID(ctx context.Context, userID int64) error {
	logger := logrus.WithContext(ctx).WithField("userID", userID)

	_, err := p.db.Model(&Authorization{}).
		Where("user_id = ? ", userID).
		Set("is_revoked = ?", true).
		Update(ctx)
	if err != nil {
		logger.WithField("error", err).Error("error updating authorization")
		return err
	}

	logger.Info("authorization updated successfully")
	return nil
}
