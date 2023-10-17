package integration

import (
	"context"
	"fmt"

	"github.com/go-pg/pg/v11"
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/ramyadmz/goauth/internal/config"
	"github.com/ramyadmz/goauth/internal/data/postgres"
	"github.com/ramyadmz/goauth/internal/service/auth"
	"github.com/ramyadmz/goauth/internal/service/credentials/jwt"
	"github.com/ramyadmz/goauth/internal/service/credentials/session"
	"github.com/ramyadmz/goauth/pkg/pb"
)

var ClientID, UserID int64
var ClientName, ClientSecret, Website, Scope, AuthCode, Token, RefreshToken string
var Username, SessionID, Email, Password string

var _ = Describe("Oauth Test Suite", func() {
	var (
		ctx        context.Context
		dal        *postgres.PostgresProvider
		userAuth   *auth.UserAuthService
		clientAuth *auth.ClientAuthService
	)

	BeforeEach(func() {
		ctx = context.Background()
		jwtConfig, err := config.NewJWTConfig()
		Expect(err).NotTo(HaveOccurred())
		tokenHandler := jwt.NewJWTHandler(jwtConfig)

		pgConfig, err := config.NewPostgresConfig()
		Expect(err).NotTo(HaveOccurred())

		options := &pg.Options{
			Addr:     fmt.Sprintf("%s:%d", pgConfig.GetHost(), pgConfig.GetPort()), // Ensure dbHost is used here
			User:     pgConfig.GetUser(),
			Password: pgConfig.GetPassword(),
			Database: pgConfig.GetDatabase(),
		}

		db := pg.Connect(options)
		dal = postgres.NewPostgresProvider(db)
		sessionHandler := session.NewSessionHandler(dal)

		// reuse dal to avoid unnecessary overhead in opening and closing multiple database connections.
		userAuth = auth.NewUserAuthService(dal, sessionHandler)
		clientAuth = auth.NewClientAuthService(dal, tokenHandler)
	})

	Context("User Registration", func() {
		It("registers and stores a new user successfully", func() {
			// Generate random credentials
			Username, Password, Email = uuid.NewString(), uuid.NewString(), uuid.NewString()

			// Attempt to register the user
			_, err := userAuth.RegisterUser(ctx, &pb.RegisterUserRequest{
				Username: Username,
				Password: Password,
				Email:    Email,
			})
			Expect(err).To(BeNil(), "User registration should complete without errors")

			By("Validating the stored user data in the database")
			user, err := dal.GetUserByUsername(ctx, Username)
			Expect(err).To(BeNil(), "The user should exist in the database after successful registration")
			UserID = user.ID

			Expect(user.Username).To(Equal(Username))
			Expect(user.HashedPassword).ToNot(BeEmpty())
			Expect(user.Email).To(Equal(Email))
		})
	})

	Context("Client Registration", func() {
		It("registers and stores a new client successfully", func() {
			ClientName, Website, Scope = uuid.NewString(), uuid.NewString(), "admin"

			rsp, err := clientAuth.RegisterClient(ctx, &pb.RegisterClientRequest{
				Name:    ClientName,
				Website: Website,
				Scope:   Scope,
			})
			Expect(err).To(BeNil(), "Client registration should complete without errors")
			ClientID = rsp.ClientId
			ClientSecret = rsp.ClientSecret

			By("Validating the stored client data in the database")
			client, err := dal.GetClientByID(ctx, rsp.ClientId)
			Expect(err).To(BeNil(), "Expected to find the user in the database")
			Expect(client.Name).To(Equal(ClientName))
			Expect(client.Website).To(Equal(Website))
			Expect(client.Scope).To(Equal(Scope))
			Expect(client.HashedSecret).ToNot(BeEmpty())
		})
	})

	Context("User Login", func() {
		It("logs in a user successfully", func() {
			rsp, err := userAuth.LoginUser(ctx, &pb.UserLoginRequest{
				Username: Username,
				Password: Password,
			})
			Expect(err).To(BeNil(), "User login should complete without errors")

			By("Validating the stored authorization record in the database")
			session, err := dal.GetSessionByID(ctx, rsp.SessionId)
			Expect(err).To(BeNil(), "Expected to find the session in the database")
			SessionID = session.ID

			user, err := dal.GetUserByID(ctx, session.UserID)
			Expect(err).To(BeNil(), "Expected to find the user in the database")

			Expect(session.UserID).To(Equal(user.ID))
			Expect(user.Username).To(Equal(Username))
		})
	})

	Context("User Consent", func() {
		It("completes user consent successfully", func() {
			_, err := userAuth.ConsentUser(ctx, &pb.UserConsentRequest{
				ClientId:  ClientID,
				SessionId: SessionID,
			})
			Expect(err).To(BeNil(), "User consent should complete without errors")

			By("Validating the stored authorization record in the database")
			auth, err := dal.GetAuthorizationCodeByUserIDAndClientID(ctx, UserID, ClientID)
			Expect(err).To(BeNil(), "Expected to find the auth code by user id and client id in the database")

			Expect(auth.AuthCode).NotTo(Equal(""))
		})

	})

	Context("Authorization Code Retrieval", func() {
		It("retrieves an authorization code successfully", func() {
			rsp, err := clientAuth.GetAuthorizationCode(ctx, &pb.GetAuthorizationCodeRequest{
				ClientId:     ClientID,
				ClientSecret: ClientSecret,
				Username:     Username,
			})
			Expect(err).To(BeNil(), "Authorization code retrieval should complete without errors")

			By("Validating the returned authorization record")
			auth, err := dal.GetAuthorizationCodeByUserIDAndClientID(ctx, UserID, ClientID)
			Expect(err).To(BeNil(), "Expected to find the auth code by user id and client id in the database")

			Expect(auth.AuthCode).To(Equal(rsp.AuthorizationCode))
			AuthCode = rsp.AuthorizationCode
		})
	})

	Context("Token Exchange", func() {
		It("exchanges an authorization code for tokens successfully", func() {
			rsp, err := clientAuth.ExchangeToken(ctx, &pb.ExchangeTokenRequest{
				ClientId:          ClientID,
				ClientSecret:      ClientSecret,
				AuthorizationCode: AuthCode,
			})
			Expect(err).To(BeNil(), "Token exchange should complete without errors")
			Expect(len(rsp.AccessToken)).NotTo(Equal(0))
			Expect(len(rsp.RefreshToken)).ToNot(Equal(0))
			Token = rsp.AccessToken
			RefreshToken = rsp.RefreshToken
		})
	})

	Context("Token Refresh", func() {
		It("refreshes an access token successfully", func() {
			rsp, err := clientAuth.RefreshToken(ctx, &pb.RefreshTokenRequest{
				RefreshToken: RefreshToken,
			})
			Expect(err).To(BeNil(), "Token refresh should complete without errors")
			Expect(len(rsp.AccessToken)).NotTo(Equal(0))
		})
	})
})
