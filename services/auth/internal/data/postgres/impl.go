package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/go-pg/pg/v11"
	"github.com/google/uuid"
	"github.com/ramyadmz/goauth/internal/data"
	"github.com/sirupsen/logrus"
)

// type dbLogger struct{}

// func (d dbLogger) BeforeQuery(ctx context.Context, q *pg.QueryEvent) (context.Context, error) {
// 	return ctx, nil
// }

// func (d dbLogger) AfterQuery(ctx context.Context, q *pg.QueryEvent) error {
// 	query, _ := q.FormattedQuery()
// 	fmt.Println(string(query))
// 	return nil
// }
// p.db.AddQueryHook(dbLogger{})

// PostgresProvider implements the AuthProvider interface using PostgreSQL as a backend.
type PostgresProvider struct {
	db *pg.DB
}

// Compile-time check to ensure PostgresProvider satisfies the data.AuthProvider interface.
var _ data.AuthProvider = new(PostgresProvider)

func NewPostgresProvider(db *pg.DB) *PostgresProvider {
	return &PostgresProvider{
		db: db,
	}
}

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
		logger.Error("Error creating user: %w", err)
		return nil, fmt.Errorf("failed to insert new user record: %w", err)
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
			logger.Error(data.ErrUserNotFound)
			return nil, data.ErrUserNotFound
		}
		logger.Error("error fetching user by userid: %w", err)
		return nil, err
	}

	logger.Info("user fetched by id successfully")
	return user.ToData(), nil
}

func (p *PostgresProvider) GetUserByUsername(ctx context.Context, username string) (*data.User, error) {
	logger := logrus.WithContext(ctx).WithField("username", username)
	user := &User{}

	err := p.db.Model(user).Where("username = ?", username).Select(ctx)
	if err != nil {
		if err == pg.ErrNoRows {
			logger.Error(data.ErrUserNotFound)
			return nil, data.ErrUserNotFound
		}
		logger.Error("error fetching user by username: %w", err)
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
		logger.Errorf("failed to insert new session record: %s", err)
		return nil, fmt.Errorf("failed to insert new session record: %w", err)
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
			logger.Error(data.ErrSessionNotFound)
			return nil, data.ErrSessionNotFound
		}
		logger.Error("error fetching session by session id: %w", err)
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
		logger.Error("error deleting session by session id: %w", err)
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
		logger.Error("error updating session: %w", err)
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
		logger.Error("error creating client: %w", err)
		return nil, fmt.Errorf("failed to insert new client record: %w", err)
	}

	logger.Info("client created successfully")
	return client.ToData(), nil
}

func (p *PostgresProvider) GetClientByID(ctx context.Context, clientID int64) (*data.Client, error) {
	logger := logrus.WithContext(ctx).WithField("clientID", clientID)
	client := &Client{
		ID: clientID,
	}

	err := p.db.Model(client).WherePK().Select(ctx)
	if err != nil {
		if err == pg.ErrNoRows {
			logger.Error(data.ErrClientNotFound)
			return nil, data.ErrClientNotFound
		}
		logger.Error("error fetching client: %w", err)
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
		IsRevoked: false,
	}

	_, err := p.db.Model(authorization).Insert(ctx)
	if err != nil {
		logger.Error("error creating authorization: %w", err)
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

	err := p.db.Model(authorization).WherePK().Select(ctx)
	if err != nil {
		if err == pg.ErrNoRows {
			logger.Warn("invalid auth code: %w", err)
			return nil, data.ErrAuthorizationNotFound
		}
		logger.Error("error fetching authorization: %w", err)
		return nil, err
	}

	logger.Info("authorization fetched successfully")
	return authorization.ToData(), nil
}

func (p *PostgresProvider) GetAuthorizationCodeByUserIDAndClientID(ctx context.Context, userID, clientID int64) (*data.Authorization, error) {
	logger := logrus.WithContext(ctx).WithField("userID", userID).WithField("clientID", clientID)
	authorization := &Authorization{}

	err := p.db.Model(authorization).Where("client_id = ? AND user_id = ?", clientID, userID).Select(ctx)
	if err != nil {
		if err == pg.ErrNoRows {
			logger.Error(data.ErrAuthorizationNotFound)
			return nil, data.ErrAuthorizationNotFound
		}
		logger.Error("error fetching authorization: %w", err)
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
		logger.Error("error updating authorization: %w", err)
		return err
	}

	logger.Info("authorization updated successfully")
	return nil
}
